//! Registration, bounded read/proposal/record/verify service seams, and
//! redacted evidence for AWS IAM Access Analyzer.

use std::{collections::BTreeMap, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsIamAccessAnalyzerError, AwsIamProviderError, Result};
use crate::model::{
    AnalysisState, AnalyzerType, AwsIamAccessAnalyzerScope, ConsentIdentity, Digest,
    FindingSummaryV2, ListFindingsV2Request, MissionIdentity, PartialReason, PermissionSnapshot,
    PolicyResourceType, PolicyType, ProjectIdentity, ProviderErrorKind, ProviderIdentity,
    ProviderProvenance, RegistrationId, RegistrationStatus, RetryEvidence, RetryPolicy, SecretKind,
    SecretReference, ValidatePolicyFinding, ValidatePolicyRequest,
};
use crate::provider::{
    AwsIamAccessAnalyzerProvider, AwsIamAccessAnalyzerTransport, ListFindingsV2Response,
    ValidatePolicyResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, EVIDENCE_LEVEL, OBJECTIVE_TYPE, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Eq, PartialEq)]
pub struct AwsIamAccessAnalyzerRegistration {
    id: RegistrationId,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: AwsIamAccessAnalyzerScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    evidence_digest: Digest,
    binding_digest: Digest,
}

impl AwsIamAccessAnalyzerRegistration {
    pub fn new(
        id: RegistrationId,
        scope: AwsIamAccessAnalyzerScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: ProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self> {
        if registration_revision == 0 {
            return Err(AwsIamAccessAnalyzerError::InvalidInput(
                "registration revision",
            ));
        }
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider,
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            evidence_digest: Digest::from_text("unsealed-aws-iam-evidence-binding"),
            binding_digest: Digest::from_text("unsealed-aws-iam-registration"),
        };
        registration.reseal();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.secret_reference.scope_digest() != &self.scope_digest
            || self.secret_reference.revision() == 0
            || self.secret_reference.kind() != SecretKind::Sigv4Iam
        {
            return Err(AwsIamAccessAnalyzerError::InvalidRegistration);
        }
        self.provider.validate()?;
        self.permission_snapshot.validate()?;
        if self.evidence_digest != self.compute_evidence_digest()
            || self.binding_digest != self.compute_binding_digest()
        {
            return Err(AwsIamAccessAnalyzerError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn id(&self) -> &RegistrationId {
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

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn scope(&self) -> &AwsIamAccessAnalyzerScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        match self.status {
            RegistrationStatus::Reversed => Err(AwsIamAccessAnalyzerError::RegistrationReversed),
            RegistrationStatus::Active => {
                self.status = RegistrationStatus::Revoked;
                self.bump_and_reseal()?;
                Ok(RegistrationTransitionEvidence::for_registration(self))
            }
            RegistrationStatus::Revoked => {
                Ok(RegistrationTransitionEvidence::for_registration(self))
            }
        }
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(AwsIamAccessAnalyzerError::RegistrationReversed);
        }
        self.status = RegistrationStatus::Reversed;
        self.bump_and_reseal()?;
        Ok(RegistrationTransitionEvidence::for_registration(self))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        match self.status {
            RegistrationStatus::Active => {
                Ok(RegistrationTransitionEvidence::for_registration(self))
            }
            RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Active;
                self.bump_and_reseal()?;
                Ok(RegistrationTransitionEvidence::for_registration(self))
            }
            RegistrationStatus::Reversed => Err(AwsIamAccessAnalyzerError::RegistrationReversed),
        }
    }

    fn bump_and_reseal(&mut self) -> Result<()> {
        self.registration_revision = self.registration_revision.checked_add(1).ok_or(
            AwsIamAccessAnalyzerError::InvalidInput("registration revision overflow"),
        )?;
        self.reseal();
        self.validate()
    }

    fn reseal(&mut self) {
        self.evidence_digest = self.compute_evidence_digest();
        self.binding_digest = self.compute_binding_digest();
    }

    fn compute_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-access-analyzer-evidence-binding/v1",
            &[
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider.digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest.as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
            ],
        )
    }

    fn compute_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-access-analyzer-registration-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider.digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest.as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "secret_revision",
                    self.secret_reference.revision().to_string(),
                ),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
            ],
        )
    }
}

impl Serialize for AwsIamAccessAnalyzerRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsIamAccessAnalyzerRegistration", 14)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("provider", &self.provider)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("scope", &SafeScope::from_scope(&self.scope))?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "secretReference",
            &SafeSecretReference {
                kind: self.secret_reference.kind(),
                reference_digest: self.secret_reference.reference_digest(),
                scope_digest: self.secret_reference.scope_digest(),
                revision: self.secret_reference.revision(),
                revoked: self.secret_reference.is_revoked(),
            },
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.end()
    }
}

impl fmt::Debug for AwsIamAccessAnalyzerRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsIamAccessAnalyzerRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider", &self.provider)
            .field("permission_digest", &self.permission_snapshot.digest)
            .field("scope_digest", &self.scope_digest)
            .field("scope", &SafeScope::from_scope(&self.scope))
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("evidence_digest", &self.evidence_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SafeSecretReference<'a> {
    kind: SecretKind,
    reference_digest: &'a Digest,
    scope_digest: &'a Digest,
    revision: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SafeScope {
    account: crate::AwsAccountId,
    region: crate::AwsRegion,
    analyzer: crate::AnalyzerArn,
    analyzer_type: AnalyzerType,
    policy_type: PolicyType,
    policy_resource_type: Option<PolicyResourceType>,
    policy_revision: crate::Revision,
    resource_digest: Digest,
    resource_type: crate::ResourceType,
    resource_owner_account: crate::AwsAccountId,
    resource_revision: crate::Revision,
    mission: MissionIdentity,
    project: ProjectIdentity,
    consent: ConsentIdentity,
}

impl SafeScope {
    fn from_scope(scope: &AwsIamAccessAnalyzerScope) -> Self {
        Self {
            account: scope.account.clone(),
            region: scope.region.clone(),
            analyzer: scope.analyzer.clone(),
            analyzer_type: scope.analyzer_type,
            policy_type: scope.policy_type,
            policy_resource_type: scope.policy_resource_type,
            policy_revision: scope.policy_revision,
            resource_digest: scope.resource.resource_digest.clone(),
            resource_type: scope.resource.resource_type,
            resource_owner_account: scope.resource.owner_account.clone(),
            resource_revision: scope.resource.revision,
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            consent: scope.consent.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationReceipt {
    pub registration_id: RegistrationId,
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub binding_digest: Digest,
    pub evidence_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationReceipt {
    fn for_registration(registration: &AwsIamAccessAnalyzerRegistration) -> Self {
        Self {
            registration_id: registration.id.clone(),
            status: registration.status,
            registration_revision: registration.registration_revision,
            binding_digest: registration.binding_digest.clone(),
            evidence_digest: registration.evidence_digest.clone(),
            reversible: true,
            revocable: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub registration_id: RegistrationId,
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub binding_digest: Digest,
    pub evidence_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationTransitionEvidence {
    fn for_registration(registration: &AwsIamAccessAnalyzerRegistration) -> Self {
        let receipt = RegistrationReceipt::for_registration(registration);
        Self {
            registration_id: receipt.registration_id,
            status: receipt.status,
            registration_revision: receipt.registration_revision,
            binding_digest: receipt.binding_digest,
            evidence_digest: receipt.evidence_digest,
            reversible: receipt.reversible,
            revocable: receipt.revocable,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AwsIamAccessAnalyzerRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, AwsIamAccessAnalyzerRegistration>,
}

impl AwsIamAccessAnalyzerRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: AwsIamAccessAnalyzerRegistration,
    ) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(AwsIamAccessAnalyzerError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&AwsIamAccessAnalyzerRegistration> {
        self.registrations
            .get(id)
            .ok_or(AwsIamAccessAnalyzerError::RegistrationUnknown)
    }

    pub fn get_mut(
        &mut self,
        id: &RegistrationId,
    ) -> Result<&mut AwsIamAccessAnalyzerRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(AwsIamAccessAnalyzerError::RegistrationUnknown)
    }

    pub fn revoke(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.revoke()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn reverse(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.reverse()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn restore(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.restore()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn iter(&self) -> impl Iterator<Item = &AwsIamAccessAnalyzerRegistration> {
        self.registrations.values()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub plugin_id: String,
    pub layer: u8,
    pub evidence_level: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub provider_api_revision: String,
    pub operations: Vec<String>,
    pub allowed_provenance: Vec<ProviderProvenance>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adoption: bool,
    pub least_privilege_certified: bool,
}

impl CapabilityDescription {
    fn layer_one() -> Self {
        Self {
            plugin_id: crate::PLUGIN_ID.to_owned(),
            layer: 1,
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            provider_api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "register_scope".to_owned(),
                "list_findings_v2_read".to_owned(),
                "list_findings_v2_proposal".to_owned(),
                "list_findings_v2_record".to_owned(),
                "list_findings_v2_verify".to_owned(),
                "validate_policy_read".to_owned(),
                "validate_policy_proposal".to_owned(),
                "validate_policy_record".to_owned(),
                "validate_policy_verify".to_owned(),
                "revoke_registration".to_owned(),
                "reverse_registration".to_owned(),
                "restore_registration".to_owned(),
            ],
            allowed_provenance: vec![
                ProviderProvenance::Recording,
                ProviderProvenance::Fake,
                ProviderProvenance::Loopback,
                ProviderProvenance::BlockedEnv,
            ],
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adoption: false,
            least_privilege_certified: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDescription {
    pub objective_type: &'static str,
    pub scope_digest: Digest,
    pub account: crate::AwsAccountId,
    pub region: crate::AwsRegion,
    pub analyzer: crate::AnalyzerArn,
    pub analyzer_type: AnalyzerType,
    pub policy_type: PolicyType,
    pub policy_resource_type: Option<PolicyResourceType>,
    pub policy_revision: crate::Revision,
    pub resource_digest: Digest,
    pub resource_type: crate::ResourceType,
    pub resource_owner_account: crate::AwsAccountId,
    pub resource_revision: crate::Revision,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub consent: ConsentIdentity,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_revision: u64,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingsEvidence {
    pub state: AnalysisState,
    pub findings: Vec<FindingSummaryV2>,
    pub pages_observed: u16,
    pub finding_count: usize,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub retry: RetryEvidence,
    pub provider_error: Option<ProviderErrorKind>,
    pub absence_is_not_proof: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

impl FindingsEvidence {
    fn new(
        state: AnalysisState,
        findings: Vec<FindingSummaryV2>,
        pages_observed: u16,
        request: &ListFindingsV2Request,
        registration: &AwsIamAccessAnalyzerRegistration,
        retry: RetryEvidence,
        provider_error: Option<ProviderErrorKind>,
    ) -> Self {
        let mut evidence = Self {
            state,
            finding_count: findings.len(),
            findings,
            pages_observed,
            filter_digest: request.filter.digest(),
            cursor_digest: request
                .next_cursor
                .as_ref()
                .map(|cursor| cursor.digest().clone()),
            request_digest: request.request_digest.clone(),
            plugin_version: registration.plugin_version.clone(),
            contract_version: registration.contract_version.clone(),
            contract_digest: registration.contract_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            provider_digest: registration.provider.digest.clone(),
            registration_digest: registration.binding_digest.clone(),
            retry,
            provider_error,
            absence_is_not_proof: true,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::from_text("unsealed-findings-evidence"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for finding in &self.findings {
            finding.validate()?;
        }
        if self.finding_count != self.findings.len()
            || !self.absence_is_not_proof
            || self.connected
            || self.native
            || self.first_party
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.compute_digest() != self.evidence_digest
        {
            return Err(AwsIamAccessAnalyzerError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn is_reviewable(&self) -> bool {
        matches!(
            self.state,
            AnalysisState::Complete | AnalysisState::EmptyNotProof
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-findings-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                (
                    "findings",
                    self.findings
                        .iter()
                        .map(|f| f.finding_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_observed.to_string()),
                ("filter", self.filter_digest.as_str().to_owned()),
                (
                    "cursor",
                    self.cursor_digest
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), |d| d.as_str().to_owned()),
                ),
                ("request", self.request_digest.as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "retry",
                    Digest::from_serialized(&self.retry).as_str().to_owned(),
                ),
                (
                    "provider_error",
                    self.provider_error
                        .map_or_else(|| "none".to_owned(), |e| format!("{e:?}")),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyValidationEvidence {
    pub state: AnalysisState,
    pub findings: Vec<ValidatePolicyFinding>,
    pub pages_observed: u16,
    pub finding_count: usize,
    pub policy_digest: Digest,
    pub policy_bytes: usize,
    pub request_digest: Digest,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub retry: RetryEvidence,
    pub provider_error: Option<ProviderErrorKind>,
    pub absence_is_not_proof: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

impl PolicyValidationEvidence {
    fn new(
        state: AnalysisState,
        findings: Vec<ValidatePolicyFinding>,
        pages_observed: u16,
        request: &ValidatePolicyRequest,
        registration: &AwsIamAccessAnalyzerRegistration,
        retry: RetryEvidence,
        provider_error: Option<ProviderErrorKind>,
    ) -> Self {
        let mut evidence = Self {
            state,
            finding_count: findings.len(),
            findings,
            pages_observed,
            policy_digest: request.policy_digest.clone(),
            policy_bytes: request.policy_bytes,
            request_digest: request.request_digest.clone(),
            plugin_version: registration.plugin_version.clone(),
            contract_version: registration.contract_version.clone(),
            contract_digest: registration.contract_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            provider_digest: registration.provider.digest.clone(),
            registration_digest: registration.binding_digest.clone(),
            retry,
            provider_error,
            absence_is_not_proof: true,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::from_text("unsealed-policy-evidence"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for finding in &self.findings {
            finding.validate()?;
        }
        if self.finding_count != self.findings.len()
            || !self.absence_is_not_proof
            || self.connected
            || self.native
            || self.first_party
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.compute_digest() != self.evidence_digest
        {
            return Err(AwsIamAccessAnalyzerError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn is_reviewable(&self) -> bool {
        matches!(
            self.state,
            AnalysisState::Complete | AnalysisState::EmptyNotProof
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-policy-validation-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                (
                    "findings",
                    self.findings
                        .iter()
                        .map(|f| f.finding_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_observed.to_string()),
                ("policy", self.policy_digest.as_str().to_owned()),
                ("policy_bytes", self.policy_bytes.to_string()),
                ("request", self.request_digest.as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "retry",
                    Digest::from_serialized(&self.retry).as_str().to_owned(),
                ),
                (
                    "provider_error",
                    self.provider_error
                        .map_or_else(|| "none".to_owned(), |e| format!("{e:?}")),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListFindingsV2Proposal {
    pub request: ListFindingsV2Request,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub proposal_digest: Digest,
}

impl ListFindingsV2Proposal {
    fn new(
        registration: &AwsIamAccessAnalyzerRegistration,
        request: ListFindingsV2Request,
    ) -> Self {
        let mut proposal = Self {
            scope_digest: registration.scope_digest.clone(),
            registration_digest: registration.binding_digest.clone(),
            provider_digest: registration.provider.digest.clone(),
            contract_digest: registration.contract_digest.clone(),
            proposal_digest: Digest::from_text("unsealed-findings-proposal"),
            request,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.compute_digest() == self.proposal_digest {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::TamperedEvidence)
        }
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-findings-proposal/v1",
            &[
                ("request", self.request.request_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatePolicyProposal {
    pub request: ValidatePolicyRequest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub proposal_digest: Digest,
}

impl ValidatePolicyProposal {
    fn new(
        registration: &AwsIamAccessAnalyzerRegistration,
        request: ValidatePolicyRequest,
    ) -> Self {
        let mut proposal = Self {
            scope_digest: registration.scope_digest.clone(),
            registration_digest: registration.binding_digest.clone(),
            provider_digest: registration.provider.digest.clone(),
            contract_digest: registration.contract_digest.clone(),
            proposal_digest: Digest::from_text("unsealed-policy-proposal"),
            request,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.compute_digest() == self.proposal_digest {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::TamperedEvidence)
        }
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-policy-proposal/v1",
            &[
                ("request", self.request.request_digest.as_str().to_owned()),
                ("policy", self.request.policy_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    ProposalTampered,
    EvidenceTampered,
    ScopeMismatch,
    RegistrationMismatch,
    ProviderMismatch,
    PermissionMismatch,
    RequestMismatch,
    MissionRevisionMismatch,
    PolicyRevisionMismatch,
    EmptyFindingSetIsNotProof,
    NonReviewableState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub verified: bool,
    pub reviewable: bool,
    pub failures: Vec<VerificationFailure>,
    pub evidence_digest: Option<Digest>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl VerificationReport {
    fn from_failures(
        failures: Vec<VerificationFailure>,
        evidence_digest: Option<Digest>,
        reviewable: bool,
    ) -> Self {
        Self {
            verified: failures.is_empty(),
            reviewable,
            failures,
            evidence_digest,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub const fn verified(&self) -> bool {
        self.verified
    }

    pub const fn reviewable(&self) -> bool {
        self.reviewable
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedFindings {
    pub idempotency_key_digest: Digest,
    pub evidence_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedPolicyValidation {
    pub idempotency_key_digest: Digest,
    pub evidence_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Default)]
pub struct AwsIamAccessAnalyzerRecordingLog {
    findings: BTreeMap<Digest, RecordedFindings>,
    policies: BTreeMap<Digest, RecordedPolicyValidation>,
}

impl AwsIamAccessAnalyzerRecordingLog {
    pub fn findings_len(&self) -> usize {
        self.findings.len()
    }

    pub fn policies_len(&self) -> usize {
        self.policies.len()
    }
}

pub type FindingsRecordingLog = AwsIamAccessAnalyzerRecordingLog;
pub type PolicyValidationRecordingLog = AwsIamAccessAnalyzerRecordingLog;

#[derive(Debug)]
pub struct AwsIamAccessAnalyzerService<T> {
    provider: AwsIamAccessAnalyzerProvider<T>,
    retry_policy: RetryPolicy,
}

impl<T: AwsIamAccessAnalyzerTransport> AwsIamAccessAnalyzerService<T> {
    pub fn new(registration: AwsIamAccessAnalyzerRegistration, transport: T) -> Result<Self> {
        Self::with_retry_policy(registration, transport, RetryPolicy::default())
    }

    pub fn with_retry_policy(
        registration: AwsIamAccessAnalyzerRegistration,
        transport: T,
        retry_policy: RetryPolicy,
    ) -> Result<Self> {
        Ok(Self {
            provider: AwsIamAccessAnalyzerProvider::new(registration, transport)?,
            retry_policy,
        })
    }

    pub fn provider(&self) -> &AwsIamAccessAnalyzerProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsIamAccessAnalyzerProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsIamAccessAnalyzerRegistration {
        self.provider.registration()
    }

    pub fn registration_mut(&mut self) -> &mut AwsIamAccessAnalyzerRegistration {
        self.provider.registration_mut()
    }

    pub fn scope(&self) -> &AwsIamAccessAnalyzerScope {
        self.registration().scope()
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription::layer_one()
    }

    pub fn describe_scope(&self) -> ScopeDescription {
        let registration = self.registration();
        let scope = registration.scope();
        ScopeDescription {
            objective_type: OBJECTIVE_TYPE,
            scope_digest: scope.digest(),
            account: scope.account.clone(),
            region: scope.region.clone(),
            analyzer: scope.analyzer.clone(),
            analyzer_type: scope.analyzer_type,
            policy_type: scope.policy_type,
            policy_resource_type: scope.policy_resource_type,
            policy_revision: scope.policy_revision,
            resource_digest: scope.resource.resource_digest.clone(),
            resource_type: scope.resource.resource_type,
            resource_owner_account: scope.resource.owner_account.clone(),
            resource_revision: scope.resource.revision,
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            consent: scope.consent.clone(),
            permission_digest: registration.permission_snapshot().digest.clone(),
            provider_digest: registration.provider.digest.clone(),
            secret_reference_digest: registration.secret_reference.reference_digest().clone(),
            evidence_digest: registration.evidence_digest.clone(),
            registration_revision: registration.registration_revision,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration_mut().revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration_mut().reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration_mut().restore()
    }

    pub fn compile_list_findings_v2_proposal(
        &self,
        request: &ListFindingsV2Request,
    ) -> Result<ListFindingsV2Proposal> {
        self.provider.ensure_ready()?;
        let request = self.prepare_findings_request(request)?;
        Ok(ListFindingsV2Proposal::new(self.registration(), request))
    }

    pub fn compile_findings_proposal(
        &self,
        request: &ListFindingsV2Request,
    ) -> Result<ListFindingsV2Proposal> {
        self.compile_list_findings_v2_proposal(request)
    }

    pub fn read_list_findings_v2(
        &mut self,
        request: &ListFindingsV2Request,
    ) -> Result<FindingsEvidence> {
        self.read_findings_v2(request)
    }

    pub fn read_findings_v2(
        &mut self,
        request: &ListFindingsV2Request,
    ) -> Result<FindingsEvidence> {
        self.provider.ensure_ready()?;
        let request = self.prepare_findings_request(request)?;
        self.bound_findings(&request)
    }

    pub fn observe_findings_v2(
        &mut self,
        request: &ListFindingsV2Request,
    ) -> Result<FindingsEvidence> {
        match self.read_findings_v2(request) {
            Ok(evidence) => Ok(evidence),
            Err(AwsIamAccessAnalyzerError::Provider(error)) => {
                let request = self.prepare_findings_request(request)?;
                let (state, kind) = state_for_provider_error(&error);
                Ok(FindingsEvidence::new(
                    state,
                    Vec::new(),
                    0,
                    &request,
                    self.registration(),
                    RetryEvidence::new(1, vec![kind])?,
                    Some(kind),
                ))
            }
            Err(error) => Err(error),
        }
    }

    pub fn compile_validate_policy_proposal(
        &self,
        request: &ValidatePolicyRequest,
    ) -> Result<ValidatePolicyProposal> {
        self.provider.ensure_ready()?;
        let request = self.prepare_policy_request(request)?;
        Ok(ValidatePolicyProposal::new(self.registration(), request))
    }

    pub fn compile_policy_validation_proposal(
        &self,
        request: &ValidatePolicyRequest,
    ) -> Result<ValidatePolicyProposal> {
        self.compile_validate_policy_proposal(request)
    }

    pub fn read_validate_policy(
        &mut self,
        request: &ValidatePolicyRequest,
    ) -> Result<PolicyValidationEvidence> {
        self.provider.ensure_ready()?;
        let request = self.prepare_policy_request(request)?;
        self.bound_policy(&request)
    }

    pub fn validate_policy(
        &mut self,
        request: &ValidatePolicyRequest,
    ) -> Result<PolicyValidationEvidence> {
        self.read_validate_policy(request)
    }

    pub fn observe_validate_policy(
        &mut self,
        request: &ValidatePolicyRequest,
    ) -> Result<PolicyValidationEvidence> {
        match self.read_validate_policy(request) {
            Ok(evidence) => Ok(evidence),
            Err(AwsIamAccessAnalyzerError::Provider(error)) => {
                let request = self.prepare_policy_request(request)?;
                let (state, kind) = state_for_provider_error(&error);
                Ok(PolicyValidationEvidence::new(
                    state,
                    Vec::new(),
                    0,
                    &request,
                    self.registration(),
                    RetryEvidence::new(1, vec![kind])?,
                    Some(kind),
                ))
            }
            Err(error) => Err(error),
        }
    }

    pub fn record_findings(
        &self,
        proposal: &ListFindingsV2Proposal,
        evidence: &FindingsEvidence,
        idempotency_key: &str,
        log: &mut AwsIamAccessAnalyzerRecordingLog,
    ) -> Result<RecordedFindings> {
        self.provider.ensure_ready()?;
        let report = self.verify_findings(proposal, evidence)?;
        if !report.verified {
            return Err(AwsIamAccessAnalyzerError::TamperedEvidence);
        }
        let key = Digest::from_text(idempotency_key);
        if let Some(existing) = log.findings.get(&key) {
            if existing.evidence_digest != evidence.evidence_digest {
                return Err(AwsIamAccessAnalyzerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let recorded = RecordedFindings {
            idempotency_key_digest: key.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            recording_digest: Digest::from_parts(
                "aws-iam-recorded-findings/v1",
                &[
                    ("key", key.as_str().to_owned()),
                    ("evidence", evidence.evidence_digest.as_str().to_owned()),
                ],
            ),
            replayed: false,
            connected: false,
            native: false,
            first_party: false,
        };
        log.findings.insert(key, recorded.clone());
        Ok(recorded)
    }

    pub fn record_list_findings_v2(
        &self,
        proposal: &ListFindingsV2Proposal,
        evidence: &FindingsEvidence,
        idempotency_key: &str,
        log: &mut AwsIamAccessAnalyzerRecordingLog,
    ) -> Result<RecordedFindings> {
        self.record_findings(proposal, evidence, idempotency_key, log)
    }

    pub fn record_policy_validation(
        &self,
        proposal: &ValidatePolicyProposal,
        evidence: &PolicyValidationEvidence,
        idempotency_key: &str,
        log: &mut AwsIamAccessAnalyzerRecordingLog,
    ) -> Result<RecordedPolicyValidation> {
        self.provider.ensure_ready()?;
        let report = self.verify_policy_validation(proposal, evidence)?;
        if !report.verified {
            return Err(AwsIamAccessAnalyzerError::TamperedEvidence);
        }
        let key = Digest::from_text(idempotency_key);
        if let Some(existing) = log.policies.get(&key) {
            if existing.evidence_digest != evidence.evidence_digest {
                return Err(AwsIamAccessAnalyzerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let recorded = RecordedPolicyValidation {
            idempotency_key_digest: key.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            recording_digest: Digest::from_parts(
                "aws-iam-recorded-policy-validation/v1",
                &[
                    ("key", key.as_str().to_owned()),
                    ("evidence", evidence.evidence_digest.as_str().to_owned()),
                ],
            ),
            replayed: false,
            connected: false,
            native: false,
            first_party: false,
        };
        log.policies.insert(key, recorded.clone());
        Ok(recorded)
    }

    pub fn verify_findings(
        &self,
        proposal: &ListFindingsV2Proposal,
        evidence: &FindingsEvidence,
    ) -> Result<VerificationReport> {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::ProposalTampered);
        }
        if evidence.validate_integrity().is_err() {
            failures.push(VerificationFailure::EvidenceTampered);
        }
        if proposal.scope_digest != self.registration().scope_digest {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.registration_digest != self.registration().binding_digest {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        if proposal.provider_digest != self.registration().provider.digest
            || evidence.provider_digest != self.registration().provider.digest
        {
            failures.push(VerificationFailure::ProviderMismatch);
        }
        if evidence.permission_digest != self.registration().permission_snapshot.digest {
            failures.push(VerificationFailure::PermissionMismatch);
        }
        if evidence.request_digest != proposal.request.request_digest
            || evidence.scope_digest != proposal.scope_digest
        {
            failures.push(VerificationFailure::RequestMismatch);
        }
        Ok(VerificationReport::from_failures(
            failures,
            Some(evidence.evidence_digest.clone()),
            evidence.is_reviewable(),
        ))
    }

    pub fn verify_list_findings_v2(
        &self,
        proposal: &ListFindingsV2Proposal,
        evidence: &FindingsEvidence,
    ) -> Result<VerificationReport> {
        self.verify_findings(proposal, evidence)
    }

    pub fn verify_policy_validation(
        &self,
        proposal: &ValidatePolicyProposal,
        evidence: &PolicyValidationEvidence,
    ) -> Result<VerificationReport> {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::ProposalTampered);
        }
        if evidence.validate_integrity().is_err() {
            failures.push(VerificationFailure::EvidenceTampered);
        }
        if proposal.scope_digest != self.registration().scope_digest {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.registration_digest != self.registration().binding_digest {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        if proposal.provider_digest != self.registration().provider.digest
            || evidence.provider_digest != self.registration().provider.digest
        {
            failures.push(VerificationFailure::ProviderMismatch);
        }
        if evidence.permission_digest != self.registration().permission_snapshot.digest {
            failures.push(VerificationFailure::PermissionMismatch);
        }
        if evidence.request_digest != proposal.request.request_digest
            || evidence.scope_digest != proposal.scope_digest
        {
            failures.push(VerificationFailure::RequestMismatch);
        }
        if evidence.policy_digest != proposal.request.policy_digest {
            failures.push(VerificationFailure::PolicyRevisionMismatch);
        }
        Ok(VerificationReport::from_failures(
            failures,
            Some(evidence.evidence_digest.clone()),
            evidence.is_reviewable(),
        ))
    }

    pub fn verify_validate_policy(
        &self,
        proposal: &ValidatePolicyProposal,
        evidence: &PolicyValidationEvidence,
    ) -> Result<VerificationReport> {
        self.verify_policy_validation(proposal, evidence)
    }

    fn prepare_findings_request(
        &self,
        request: &ListFindingsV2Request,
    ) -> Result<ListFindingsV2Request> {
        if request.scope_digest != *self.registration().scope_digest()
            || request.analyzer_arn != self.scope().analyzer
            || request.mission_revision != self.scope().mission.revision
        {
            return Err(AwsIamAccessAnalyzerError::ScopeMismatch);
        }
        let placeholder = Digest::from_text("permission-fence-placeholder");
        if request.permission_digest != self.registration().permission_snapshot.digest
            && request.permission_digest != placeholder
        {
            return Err(AwsIamAccessAnalyzerError::PermissionFenceViolation);
        }
        Ok(request
            .clone()
            .with_permission_digest(self.registration().permission_snapshot.digest.clone()))
    }

    fn prepare_policy_request(
        &self,
        request: &ValidatePolicyRequest,
    ) -> Result<ValidatePolicyRequest> {
        if request.scope_digest != *self.registration().scope_digest()
            || request.policy_type != self.scope().policy_type
            || request.policy_resource_type != self.scope().policy_resource_type
            || request.policy_revision != self.scope().policy_revision
        {
            return Err(AwsIamAccessAnalyzerError::ScopeMismatch);
        }
        let placeholder = Digest::from_text("permission-fence-placeholder");
        if request.permission_digest != self.registration().permission_snapshot.digest
            && request.permission_digest != placeholder
        {
            return Err(AwsIamAccessAnalyzerError::PermissionFenceViolation);
        }
        Ok(request
            .clone()
            .with_permission_digest(self.registration().permission_snapshot.digest.clone()))
    }

    #[allow(unused_assignments)]
    fn bound_findings(&mut self, request: &ListFindingsV2Request) -> Result<FindingsEvidence> {
        let mut current = request.clone();
        let mut findings = Vec::new();
        let mut pages_observed = 0_u16;
        let mut state = None;
        let mut provider_error = None;
        let mut retries = RetryAccumulator::new(self.retry_policy.max_backoff_millis);
        loop {
            if pages_observed >= current.max_pages {
                state = Some(AnalysisState::Partial(PartialReason::PageBudgetExhausted));
                break;
            }
            let response = self.call_findings_with_retry(&current, &mut retries);
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    if error == AwsIamProviderError::MalformedResponse {
                        state = Some(AnalysisState::Partial(PartialReason::MalformedFinding));
                    } else if error == AwsIamProviderError::MissingFixture {
                        state = Some(AnalysisState::ProviderUnknown(
                            crate::ProviderUnknownReason::MissingFixture,
                        ));
                    } else {
                        return Err(AwsIamAccessAnalyzerError::Provider(error));
                    }
                    provider_error = Some(error.kind());
                    break;
                }
            };
            pages_observed = pages_observed.saturating_add(1);
            if findings.len().saturating_add(response.findings.len()) > current.max_findings {
                state = Some(AnalysisState::Partial(
                    PartialReason::FindingBudgetExhausted,
                ));
                break;
            }
            findings.extend(response.findings);
            if let Some(cursor) = response.next_cursor {
                if pages_observed >= current.max_pages {
                    state = Some(AnalysisState::Partial(PartialReason::PageBudgetExhausted));
                    break;
                }
                current = current.next_page(cursor)?;
            } else {
                state = Some(if findings.is_empty() {
                    AnalysisState::EmptyNotProof
                } else {
                    AnalysisState::Complete
                });
                break;
            }
        }
        let retry = retries.finish()?;
        Ok(FindingsEvidence::new(
            state.unwrap_or(AnalysisState::Partial(
                PartialReason::CursorEndedUnexpectedly,
            )),
            findings,
            pages_observed,
            request,
            self.registration(),
            retry,
            provider_error,
        ))
    }

    #[allow(unused_assignments)]
    fn bound_policy(
        &mut self,
        request: &ValidatePolicyRequest,
    ) -> Result<PolicyValidationEvidence> {
        let mut current = request.clone();
        let mut findings = Vec::new();
        let mut pages_observed = 0_u16;
        let mut state = None;
        let mut provider_error = None;
        let mut retries = RetryAccumulator::new(self.retry_policy.max_backoff_millis);
        loop {
            if pages_observed >= current.max_pages {
                state = Some(AnalysisState::Partial(PartialReason::PageBudgetExhausted));
                break;
            }
            let response = match self.call_policy_with_retry(&current, &mut retries) {
                Ok(response) => response,
                Err(error) => {
                    if error == AwsIamProviderError::MalformedResponse {
                        state = Some(AnalysisState::Partial(PartialReason::MalformedFinding));
                    } else if error == AwsIamProviderError::MissingFixture {
                        state = Some(AnalysisState::ProviderUnknown(
                            crate::ProviderUnknownReason::MissingFixture,
                        ));
                    } else {
                        return Err(AwsIamAccessAnalyzerError::Provider(error));
                    }
                    provider_error = Some(error.kind());
                    break;
                }
            };
            pages_observed = pages_observed.saturating_add(1);
            if findings.len().saturating_add(response.findings.len()) > current.max_findings {
                state = Some(AnalysisState::Partial(
                    PartialReason::FindingBudgetExhausted,
                ));
                break;
            }
            findings.extend(response.findings);
            if let Some(cursor) = response.next_cursor {
                if pages_observed >= current.max_pages {
                    state = Some(AnalysisState::Partial(PartialReason::PageBudgetExhausted));
                    break;
                }
                current = current.next_page(cursor)?;
            } else {
                state = Some(if findings.is_empty() {
                    AnalysisState::EmptyNotProof
                } else {
                    AnalysisState::Complete
                });
                break;
            }
        }
        let retry = retries.finish()?;
        Ok(PolicyValidationEvidence::new(
            state.unwrap_or(AnalysisState::Partial(
                PartialReason::CursorEndedUnexpectedly,
            )),
            findings,
            pages_observed,
            request,
            self.registration(),
            retry,
            provider_error,
        ))
    }

    fn call_findings_with_retry(
        &mut self,
        request: &ListFindingsV2Request,
        retries: &mut RetryAccumulator,
    ) -> std::result::Result<ListFindingsV2Response, AwsIamProviderError> {
        let mut attempt = 0_u8;
        loop {
            attempt = attempt.saturating_add(1);
            match self.provider.list_findings_v2(request) {
                Ok(response) => {
                    retries.observe_attempt(attempt);
                    return Ok(response);
                }
                Err(AwsIamAccessAnalyzerError::Provider(error)) => {
                    retries.observe_error(attempt, error.kind());
                    if error.retryable() && attempt < self.retry_policy.max_attempts {
                        continue;
                    }
                    return Err(error);
                }
                Err(_error) => return Err(AwsIamProviderError::ProviderUnknown),
            }
        }
    }

    fn call_policy_with_retry(
        &mut self,
        request: &ValidatePolicyRequest,
        retries: &mut RetryAccumulator,
    ) -> std::result::Result<ValidatePolicyResponse, AwsIamProviderError> {
        let mut attempt = 0_u8;
        loop {
            attempt = attempt.saturating_add(1);
            match self.provider.validate_policy(request) {
                Ok(response) => {
                    retries.observe_attempt(attempt);
                    return Ok(response);
                }
                Err(AwsIamAccessAnalyzerError::Provider(error)) => {
                    retries.observe_error(attempt, error.kind());
                    if error.retryable() && attempt < self.retry_policy.max_attempts {
                        continue;
                    }
                    return Err(error);
                }
                Err(_) => return Err(AwsIamProviderError::ProviderUnknown),
            }
        }
    }
}

pub type AwsIamAccessAnalyzerResultService<T> = AwsIamAccessAnalyzerService<T>;

struct RetryAccumulator {
    attempts: u8,
    errors: Vec<ProviderErrorKind>,
    backoff_millis: u64,
    max_backoff_millis: u64,
}

impl RetryAccumulator {
    fn new(max_backoff_millis: u64) -> Self {
        Self {
            attempts: 0,
            errors: Vec::new(),
            backoff_millis: 0,
            max_backoff_millis,
        }
    }

    fn observe_attempt(&mut self, attempt: u8) {
        self.attempts = self.attempts.max(attempt).min(crate::MAX_RETRY_ATTEMPTS);
    }

    fn observe_error(&mut self, attempt: u8, error: ProviderErrorKind) {
        self.observe_attempt(attempt);
        let exponent = u32::from(attempt.saturating_sub(1).min(6));
        let delay = 100_u64.saturating_mul(1_u64 << exponent);
        self.backoff_millis = self
            .backoff_millis
            .saturating_add(delay)
            .min(self.max_backoff_millis);
        if self.errors.len() < usize::from(crate::MAX_RETRY_ATTEMPTS) {
            self.errors.push(error);
        }
    }

    fn finish(self) -> Result<RetryEvidence> {
        RetryEvidence::new(self.attempts.max(1), self.errors)?
            .with_backoff_millis(self.backoff_millis)
    }
}

fn state_for_provider_error(error: &AwsIamProviderError) -> (AnalysisState, ProviderErrorKind) {
    let kind = error.kind();
    let state = match error {
        AwsIamProviderError::BlockedEnv => AnalysisState::BlockedEnv,
        AwsIamProviderError::MalformedResponse => {
            AnalysisState::Partial(PartialReason::MalformedFinding)
        }
        AwsIamProviderError::MissingFixture => {
            AnalysisState::ProviderUnknown(crate::ProviderUnknownReason::MissingFixture)
        }
        AwsIamProviderError::ServerError { .. } => {
            AnalysisState::ProviderUnknown(crate::ProviderUnknownReason::ServerError)
        }
        AwsIamProviderError::Timeout => {
            AnalysisState::ProviderUnknown(crate::ProviderUnknownReason::Timeout)
        }
        AwsIamProviderError::ProviderUnknown
        | AwsIamProviderError::BadRequest
        | AwsIamProviderError::Unauthorized
        | AwsIamProviderError::Forbidden
        | AwsIamProviderError::NotFound
        | AwsIamProviderError::Conflict
        | AwsIamProviderError::RateLimited { .. } => {
            AnalysisState::ProviderUnknown(crate::ProviderUnknownReason::ProviderUnknown)
        }
    };
    (state, kind)
}
