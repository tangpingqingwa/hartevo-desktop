//! Public-key-only root authorization and lifecycle validation for Signed Recipes.
//!
//! The checked contract deliberately has no accepted human-operation authority
//! references and no lifecycle admission registrations. Production callers can
//! therefore validate neither a provision nor a mutation yet. Tests use a
//! private synthetic admission seam to exercise the public-key state machine;
//! that seam is never compiled into production code.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{ProjectId, TenantId};
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::BrowserRecipeKeyPurpose;
#[cfg(test)]
use super::TrustedBrowserRecipeKey;
use crate::workspace::is_bounded_identifier;

const AUTHORITY_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const KEY_REVISION_INITIAL: u64 = 1;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

const CONTRACT_SCHEMA_VERSION: &str = "hartevo-browser-recipe-authority/v1";
const CONTRACT_VERSION: &str = "recipe-authority-d01a/v1";
const PERMIT_CANDIDATE_MAX_TTL_SECONDS: u64 = 60;

const SNAPSHOT_DOMAIN: &str = "hartevo-browser-recipe-authority-snapshot/v1";
const LIFECYCLE_AUTHORITY_DOMAIN: &str = "hartevo-browser-recipe-lifecycle-authority-binding/v1";
const ROOT_PROVISIONING_DOMAIN: &str = "hartevo-browser-recipe-root-provisioning/v1";
const ROOT_ROTATION_DOMAIN: &str = "hartevo-browser-recipe-root-rotation/v1";
const LEAF_AUTHORIZATION_DOMAIN: &str = "hartevo-browser-recipe-leaf-authorization/v1";
const LEAF_ROTATION_DOMAIN: &str = "hartevo-browser-recipe-leaf-rotation/v1";
const KEY_RETIREMENT_DOMAIN: &str = "hartevo-browser-recipe-key-retirement/v1";
const KEY_REVOCATION_DOMAIN: &str = "hartevo-browser-recipe-key-revocation/v1";
const KEY_COMPROMISE_DOMAIN: &str = "hartevo-browser-recipe-key-compromise/v1";
const ROOT_POSSESSION_DOMAIN: &str = "hartevo-browser-recipe-root-possession/v1";
const LEAF_POSSESSION_DOMAIN: &str = "hartevo-browser-recipe-leaf-possession/v1";
const CANDIDATE_DOMAIN: &str = "hartevo-browser-recipe-candidate/v1";
const PROMOTION_DOMAIN: &str = "hartevo-browser-recipe-promotion/v1";

#[cfg(test)]
const CURRENT_A3_HUMAN_SCHEMA: &str = "hartevo-human-operation-authority-contract/v1";
#[cfg(test)]
const CURRENT_A3_HUMAN_VERSION: &str = "human-operation-authority-e1/v1";
#[cfg(test)]
const CURRENT_A3_HUMAN_DIGEST: &str =
    "d067c9430e80d7b4331442a4fecee340c1c354fd2b33a11ca311ca579c48b479";

const CONTRACT_JSON: &str = include_str!("../../../contracts/browser/recipe-authority.v1.json");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SnapshotAuthorityKind {
    PublicSnapshotValidationOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SecretMaterialPolicy {
    Forbidden,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EmptyReferenceBehavior {
    DenyLifecycleAdmission,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityKeyPurpose {
    RootAuthority,
    CandidatePublisher,
    ProductionRelease,
}

impl AuthorityKeyPurpose {
    const ALL: [Self; 3] = [
        Self::RootAuthority,
        Self::CandidatePublisher,
        Self::ProductionRelease,
    ];
}

impl From<BrowserRecipeKeyPurpose> for AuthorityKeyPurpose {
    fn from(value: BrowserRecipeKeyPurpose) -> Self {
        match value {
            BrowserRecipeKeyPurpose::CandidatePublisher => Self::CandidatePublisher,
            BrowserRecipeKeyPurpose::ProductionRelease => Self::ProductionRelease,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityLifecycleState {
    Active,
    Retired,
    Revoked,
    Compromised,
}

impl AuthorityLifecycleState {
    const ALL: [Self; 4] = [
        Self::Active,
        Self::Retired,
        Self::Revoked,
        Self::Compromised,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityMutationKind {
    ProvisionRoot,
    RotateRoot,
    AuthorizeLeaf,
    RotateLeaf,
    RetireKey,
    RevokeKey,
    RecordCompromise,
}

impl AuthorityMutationKind {
    const ALL: [Self; 7] = [
        Self::ProvisionRoot,
        Self::RotateRoot,
        Self::AuthorizeLeaf,
        Self::RotateLeaf,
        Self::RetireKey,
        Self::RevokeKey,
        Self::RecordCompromise,
    ];

    const fn domain(self) -> &'static str {
        match self {
            Self::ProvisionRoot => ROOT_PROVISIONING_DOMAIN,
            Self::RotateRoot => ROOT_ROTATION_DOMAIN,
            Self::AuthorizeLeaf => LEAF_AUTHORIZATION_DOMAIN,
            Self::RotateLeaf => LEAF_ROTATION_DOMAIN,
            Self::RetireKey => KEY_RETIREMENT_DOMAIN,
            Self::RevokeKey => KEY_REVOCATION_DOMAIN,
            Self::RecordCompromise => KEY_COMPROMISE_DOMAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleAuthorityKind {
    RecipeRootLifecycle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleDecision {
    Approve,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TargetBindingKind {
    NewRoot,
    ExistingRootAndNewRoot,
    NewLeaf,
    ExistingLeafAndNewLeaf,
    ExistingKey,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum SignatureProofKind {
    RootSelfPossession,
    PredecessorRootAuthorization,
    SuccessorRootPossession,
    CurrentRootAuthorization,
    NewLeafPossession,
    SealedLifecycleAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HumanOperationAuthorityReference {
    schema_version: String,
    contract_version: String,
    contract_digest: String,
    operation_kinds: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifecycleAdmissionRegistration {
    authority: LifecycleAuthorityKind,
    reference: HumanOperationAuthorityReference,
    issuer_id: String,
    issuer_version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DigestDomains {
    snapshot: String,
    lifecycle_authority_binding: String,
    root_provisioning: String,
    root_rotation: String,
    leaf_authorization: String,
    leaf_rotation: String,
    key_retirement: String,
    key_revocation: String,
    key_compromise: String,
    root_possession: String,
    leaf_possession: String,
    candidate: String,
    promotion: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetBindings {
    provision_root: TargetBindingKind,
    rotate_root: TargetBindingKind,
    authorize_leaf: TargetBindingKind,
    rotate_leaf: TargetBindingKind,
    retire_key: TargetBindingKind,
    revoke_key: TargetBindingKind,
    record_compromise: TargetBindingKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignatureBindings {
    provision_root: Vec<SignatureProofKind>,
    rotate_root: Vec<SignatureProofKind>,
    authorize_leaf: Vec<SignatureProofKind>,
    rotate_leaf: Vec<SignatureProofKind>,
    retire_key: Vec<SignatureProofKind>,
    revoke_key: Vec<SignatureProofKind>,
    record_compromise: Vec<SignatureProofKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserRecipeAuthorityContract {
    schema_version: String,
    contract_version: String,
    authority: SnapshotAuthorityKind,
    secret_material: SecretMaterialPolicy,
    snapshot_freshness_authority: bool,
    production_dispatch: bool,
    permit_candidate_max_ttl_seconds: u64,
    empty_reference_behavior: EmptyReferenceBehavior,
    required_authority_kind: LifecycleAuthorityKind,
    accepted_human_operation_authority_references: Vec<HumanOperationAuthorityReference>,
    lifecycle_admission_registrations: Vec<LifecycleAdmissionRegistration>,
    key_purposes: Vec<AuthorityKeyPurpose>,
    lifecycle_states: Vec<AuthorityLifecycleState>,
    mutation_kinds: Vec<AuthorityMutationKind>,
    digest_domains: DigestDomains,
    target_bindings: TargetBindings,
    signature_bindings: SignatureBindings,
}

impl BrowserRecipeAuthorityContract {
    fn baseline() -> Result<Self, BrowserRecipeAuthorityError> {
        Self::from_json(CONTRACT_JSON)
    }

    fn from_json(value: &str) -> Result<Self, BrowserRecipeAuthorityError> {
        let contract = serde_json::from_str::<Self>(value)
            .map_err(|_| BrowserRecipeAuthorityError::InvalidContractDocument)?;
        contract.validate()?;
        Ok(contract)
    }

    fn validate(&self) -> Result<(), BrowserRecipeAuthorityError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.authority != SnapshotAuthorityKind::PublicSnapshotValidationOnly
            || self.secret_material != SecretMaterialPolicy::Forbidden
            || self.snapshot_freshness_authority
            || self.production_dispatch
            || self.permit_candidate_max_ttl_seconds != PERMIT_CANDIDATE_MAX_TTL_SECONDS
            || self.empty_reference_behavior != EmptyReferenceBehavior::DenyLifecycleAdmission
            || self.required_authority_kind != LifecycleAuthorityKind::RecipeRootLifecycle
            || !self
                .accepted_human_operation_authority_references
                .is_empty()
            || !self.lifecycle_admission_registrations.is_empty()
        {
            return Err(BrowserRecipeAuthorityError::InvalidAuthorityBoundary);
        }
        validate_exact_set(
            &self.key_purposes,
            &AuthorityKeyPurpose::ALL,
            "key purposes",
        )?;
        validate_exact_set(
            &self.lifecycle_states,
            &AuthorityLifecycleState::ALL,
            "lifecycle states",
        )?;
        validate_exact_set(
            &self.mutation_kinds,
            &AuthorityMutationKind::ALL,
            "mutation kinds",
        )?;
        if self.digest_domains
            != (DigestDomains {
                snapshot: SNAPSHOT_DOMAIN.into(),
                lifecycle_authority_binding: LIFECYCLE_AUTHORITY_DOMAIN.into(),
                root_provisioning: ROOT_PROVISIONING_DOMAIN.into(),
                root_rotation: ROOT_ROTATION_DOMAIN.into(),
                leaf_authorization: LEAF_AUTHORIZATION_DOMAIN.into(),
                leaf_rotation: LEAF_ROTATION_DOMAIN.into(),
                key_retirement: KEY_RETIREMENT_DOMAIN.into(),
                key_revocation: KEY_REVOCATION_DOMAIN.into(),
                key_compromise: KEY_COMPROMISE_DOMAIN.into(),
                root_possession: ROOT_POSSESSION_DOMAIN.into(),
                leaf_possession: LEAF_POSSESSION_DOMAIN.into(),
                candidate: CANDIDATE_DOMAIN.into(),
                promotion: PROMOTION_DOMAIN.into(),
            })
        {
            return Err(BrowserRecipeAuthorityError::InvalidDigestDomains);
        }
        if self.target_bindings
            != (TargetBindings {
                provision_root: TargetBindingKind::NewRoot,
                rotate_root: TargetBindingKind::ExistingRootAndNewRoot,
                authorize_leaf: TargetBindingKind::NewLeaf,
                rotate_leaf: TargetBindingKind::ExistingLeafAndNewLeaf,
                retire_key: TargetBindingKind::ExistingKey,
                revoke_key: TargetBindingKind::ExistingKey,
                record_compromise: TargetBindingKind::ExistingKey,
            })
        {
            return Err(BrowserRecipeAuthorityError::InvalidTargetBindings);
        }
        let expected_signatures = SignatureBindings {
            provision_root: vec![
                SignatureProofKind::RootSelfPossession,
                SignatureProofKind::SealedLifecycleAuthority,
            ],
            rotate_root: vec![
                SignatureProofKind::PredecessorRootAuthorization,
                SignatureProofKind::SuccessorRootPossession,
                SignatureProofKind::SealedLifecycleAuthority,
            ],
            authorize_leaf: vec![
                SignatureProofKind::CurrentRootAuthorization,
                SignatureProofKind::NewLeafPossession,
                SignatureProofKind::SealedLifecycleAuthority,
            ],
            rotate_leaf: vec![
                SignatureProofKind::CurrentRootAuthorization,
                SignatureProofKind::NewLeafPossession,
                SignatureProofKind::SealedLifecycleAuthority,
            ],
            retire_key: vec![
                SignatureProofKind::CurrentRootAuthorization,
                SignatureProofKind::SealedLifecycleAuthority,
            ],
            revoke_key: vec![
                SignatureProofKind::CurrentRootAuthorization,
                SignatureProofKind::SealedLifecycleAuthority,
            ],
            record_compromise: vec![SignatureProofKind::SealedLifecycleAuthority],
        };
        if self.signature_bindings != expected_signatures {
            return Err(BrowserRecipeAuthorityError::InvalidSignatureBindings);
        }
        Ok(())
    }

    fn deny_unregistered_admission(&self) -> Result<(), BrowserRecipeAuthorityError> {
        self.validate()?;
        Err(BrowserRecipeAuthorityError::LifecycleAdmissionDenied)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExistingKeyTarget {
    key_id: String,
    expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NewRootTarget {
    root_key_id: String,
    expected_absent: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NewLeafTarget {
    leaf_key_id: String,
    purpose: AuthorityKeyPurpose,
    expected_absent: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RootRotationTargets {
    predecessor: ExistingKeyTarget,
    successor: NewRootTarget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LeafRotationTargets {
    predecessor: ExistingKeyTarget,
    successor: NewLeafTarget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LifecycleOperationTarget {
    ExistingKey(ExistingKeyTarget),
    NewRoot(NewRootTarget),
    NewLeaf(NewLeafTarget),
    ExistingRootAndNewRoot(RootRotationTargets),
    ExistingLeafAndNewLeaf(LeafRotationTargets),
}

impl ExistingKeyTarget {
    fn validate(&self) -> Result<(), BrowserRecipeAuthorityError> {
        if !valid_id(&self.key_id) || self.expected_revision == 0 {
            return Err(BrowserRecipeAuthorityError::InvalidMutationTarget);
        }
        Ok(())
    }
}

impl NewRootTarget {
    fn validate(&self) -> Result<(), BrowserRecipeAuthorityError> {
        if !valid_id(&self.root_key_id) || !self.expected_absent {
            return Err(BrowserRecipeAuthorityError::InvalidMutationTarget);
        }
        Ok(())
    }
}

impl NewLeafTarget {
    fn validate(&self) -> Result<(), BrowserRecipeAuthorityError> {
        if !valid_id(&self.leaf_key_id)
            || !self.expected_absent
            || self.purpose == AuthorityKeyPurpose::RootAuthority
        {
            return Err(BrowserRecipeAuthorityError::InvalidMutationTarget);
        }
        Ok(())
    }
}

impl LifecycleOperationTarget {
    fn validate(&self) -> Result<(), BrowserRecipeAuthorityError> {
        match self {
            Self::ExistingKey(target) => target.validate(),
            Self::NewRoot(target) => target.validate(),
            Self::NewLeaf(target) => target.validate(),
            Self::ExistingRootAndNewRoot(targets) => {
                targets.predecessor.validate()?;
                targets.successor.validate()?;
                if targets.predecessor.key_id == targets.successor.root_key_id {
                    return Err(BrowserRecipeAuthorityError::InvalidMutationTarget);
                }
                Ok(())
            }
            Self::ExistingLeafAndNewLeaf(targets) => {
                targets.predecessor.validate()?;
                targets.successor.validate()?;
                if targets.predecessor.key_id == targets.successor.leaf_key_id {
                    return Err(BrowserRecipeAuthorityError::InvalidMutationTarget);
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AuthorityOperation {
    ProvisionRoot {
        target: NewRootTarget,
        generation: u64,
        public_key_hex: String,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    RotateRoot {
        target: RootRotationTargets,
        successor_generation: u64,
        successor_public_key_hex: String,
        successor_valid_from: DateTime<Utc>,
        successor_valid_until: DateTime<Utc>,
    },
    AuthorizeLeaf {
        authorizing_root: ExistingKeyTarget,
        target: NewLeafTarget,
        public_key_hex: String,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    RotateLeaf {
        authorizing_root: ExistingKeyTarget,
        target: LeafRotationTargets,
        successor_public_key_hex: String,
        successor_valid_from: DateTime<Utc>,
        successor_valid_until: DateTime<Utc>,
    },
    RetireKey {
        authorizing_root: ExistingKeyTarget,
        target: ExistingKeyTarget,
    },
    RevokeKey {
        authorizing_root: ExistingKeyTarget,
        target: ExistingKeyTarget,
    },
    RecordCompromise {
        target: ExistingKeyTarget,
        compromised_from: DateTime<Utc>,
    },
}

impl AuthorityOperation {
    const fn kind(&self) -> AuthorityMutationKind {
        match self {
            Self::ProvisionRoot { .. } => AuthorityMutationKind::ProvisionRoot,
            Self::RotateRoot { .. } => AuthorityMutationKind::RotateRoot,
            Self::AuthorizeLeaf { .. } => AuthorityMutationKind::AuthorizeLeaf,
            Self::RotateLeaf { .. } => AuthorityMutationKind::RotateLeaf,
            Self::RetireKey { .. } => AuthorityMutationKind::RetireKey,
            Self::RevokeKey { .. } => AuthorityMutationKind::RevokeKey,
            Self::RecordCompromise { .. } => AuthorityMutationKind::RecordCompromise,
        }
    }

    fn target(&self) -> LifecycleOperationTarget {
        match self {
            Self::ProvisionRoot { target, .. } => LifecycleOperationTarget::NewRoot(target.clone()),
            Self::RotateRoot { target, .. } => {
                LifecycleOperationTarget::ExistingRootAndNewRoot(target.clone())
            }
            Self::AuthorizeLeaf { target, .. } => LifecycleOperationTarget::NewLeaf(target.clone()),
            Self::RotateLeaf { target, .. } => {
                LifecycleOperationTarget::ExistingLeafAndNewLeaf(target.clone())
            }
            Self::RetireKey { target, .. }
            | Self::RevokeKey { target, .. }
            | Self::RecordCompromise { target, .. } => {
                LifecycleOperationTarget::ExistingKey(target.clone())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifecycleAuthorityBinding {
    human_operation_authority: HumanOperationAuthorityReference,
    authority_kind: LifecycleAuthorityKind,
    decision: LifecycleDecision,
    operation_kind: AuthorityMutationKind,
    tenant_id: TenantId,
    project_id: ProjectId,
    target: LifecycleOperationTarget,
    issued_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    operation_digest: String,
    capability_digest: String,
    authority_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AuthoritySignatureBundle {
    ProvisionRoot {
        root_self_possession_hex: String,
    },
    RotateRoot {
        predecessor_root_authorization_hex: String,
        successor_root_possession_hex: String,
    },
    AuthorizeLeaf {
        current_root_authorization_hex: String,
        new_leaf_possession_hex: String,
    },
    RotateLeaf {
        current_root_authorization_hex: String,
        new_leaf_possession_hex: String,
    },
    RetireKey {
        current_root_authorization_hex: String,
    },
    RevokeKey {
        current_root_authorization_hex: String,
    },
    RecordCompromise {},
}

impl AuthoritySignatureBundle {
    const fn kind(&self) -> AuthorityMutationKind {
        match self {
            Self::ProvisionRoot { .. } => AuthorityMutationKind::ProvisionRoot,
            Self::RotateRoot { .. } => AuthorityMutationKind::RotateRoot,
            Self::AuthorizeLeaf { .. } => AuthorityMutationKind::AuthorizeLeaf,
            Self::RotateLeaf { .. } => AuthorityMutationKind::RotateLeaf,
            Self::RetireKey { .. } => AuthorityMutationKind::RetireKey,
            Self::RevokeKey { .. } => AuthorityMutationKind::RevokeKey,
            Self::RecordCompromise {} => AuthorityMutationKind::RecordCompromise,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserRecipeAuthorityMutation {
    schema_version: u32,
    tenant_id: TenantId,
    project_id: ProjectId,
    mutation_id: String,
    sequence: u64,
    recorded_at: DateTime<Utc>,
    operation: AuthorityOperation,
    lifecycle_authority: LifecycleAuthorityBinding,
    signatures: AuthoritySignatureBundle,
}

impl BrowserRecipeAuthorityMutation {
    fn operation_digest(&self) -> Result<String, BrowserRecipeAuthorityError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct DigestMaterial<'a> {
            domain: &'static str,
            schema_version: u32,
            tenant_id: &'a TenantId,
            project_id: &'a ProjectId,
            mutation_id: &'a str,
            sequence: u64,
            recorded_at: DateTime<Utc>,
            operation: &'a AuthorityOperation,
        }
        digest_json(&DigestMaterial {
            domain: self.operation.kind().domain(),
            schema_version: self.schema_version,
            tenant_id: &self.tenant_id,
            project_id: &self.project_id,
            mutation_id: &self.mutation_id,
            sequence: self.sequence,
            recorded_at: self.recorded_at,
            operation: &self.operation,
        })
    }

    fn validate_binding(&self) -> Result<(), BrowserRecipeAuthorityError> {
        if self.schema_version != AUTHORITY_SNAPSHOT_SCHEMA_VERSION
            || !valid_id(&self.mutation_id)
            || self.sequence == 0
            || self.operation.kind() != self.signatures.kind()
        {
            return Err(BrowserRecipeAuthorityError::InvalidMutation);
        }
        let operation_digest = self.operation_digest()?;
        let binding = &self.lifecycle_authority;
        binding.target.validate()?;
        let human_reference = &binding.human_operation_authority;
        if binding.authority_kind != LifecycleAuthorityKind::RecipeRootLifecycle
            || binding.decision != LifecycleDecision::Approve
            || binding.operation_kind != self.operation.kind()
            || binding.tenant_id != self.tenant_id
            || binding.project_id != self.project_id
            || binding.target != self.operation.target()
            || binding.issued_at > self.recorded_at
            || self.recorded_at >= binding.valid_until
            || binding.operation_digest != operation_digest
            || !is_sha256(&binding.capability_digest)
            || !is_sha256(&binding.authority_digest)
            || !is_sha256(&human_reference.contract_digest)
            || human_reference.operation_kinds != ["recipe_root_lifecycle"]
            || binding.authority_digest != binding.canonical_digest()?
        {
            return Err(BrowserRecipeAuthorityError::InvalidLifecycleAuthority);
        }
        Ok(())
    }
}

impl LifecycleAuthorityBinding {
    fn canonical_digest(&self) -> Result<String, BrowserRecipeAuthorityError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct DigestMaterial<'a> {
            domain: &'static str,
            human_operation_authority: &'a HumanOperationAuthorityReference,
            authority_kind: LifecycleAuthorityKind,
            decision: LifecycleDecision,
            operation_kind: AuthorityMutationKind,
            tenant_id: &'a TenantId,
            project_id: &'a ProjectId,
            target: &'a LifecycleOperationTarget,
            issued_at: DateTime<Utc>,
            valid_until: DateTime<Utc>,
            operation_digest: &'a str,
            capability_digest: &'a str,
        }
        digest_json(&DigestMaterial {
            domain: LIFECYCLE_AUTHORITY_DOMAIN,
            human_operation_authority: &self.human_operation_authority,
            authority_kind: self.authority_kind,
            decision: self.decision,
            operation_kind: self.operation_kind,
            tenant_id: &self.tenant_id,
            project_id: &self.project_id,
            target: &self.target,
            issued_at: self.issued_at,
            valid_until: self.valid_until,
            operation_digest: &self.operation_digest,
            capability_digest: &self.capability_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserRecipeAuthoritySnapshot {
    schema_version: u32,
    tenant_id: TenantId,
    project_id: ProjectId,
    snapshot_revision: u64,
    snapshot_as_of: DateTime<Utc>,
    mutations: Vec<BrowserRecipeAuthorityMutation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BrowserRecipeAuthoritySnapshotExpectation {
    tenant_id: TenantId,
    project_id: ProjectId,
    snapshot_revision: u64,
    snapshot_as_of: DateTime<Utc>,
    snapshot_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotValidatedAuthorization {
    tenant_id: TenantId,
    project_id: ProjectId,
    snapshot_revision: u64,
    snapshot_as_of: DateTime<Utc>,
    snapshot_digest: String,
    state_digest: String,
    snapshot_freshness_authority: bool,
    production_dispatch: bool,
}

impl BrowserRecipeAuthoritySnapshot {
    fn digest(&self) -> Result<String, BrowserRecipeAuthorityError> {
        digest_json(&(SNAPSHOT_DOMAIN, self))
    }

    #[cfg(test)]
    fn expectation(
        &self,
    ) -> Result<BrowserRecipeAuthoritySnapshotExpectation, BrowserRecipeAuthorityError> {
        Ok(BrowserRecipeAuthoritySnapshotExpectation {
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            snapshot_revision: self.snapshot_revision,
            snapshot_as_of: self.snapshot_as_of,
            snapshot_digest: self.digest()?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorityDelegation {
    authorization_digest: String,
    operation_digest: String,
    authorizing_root_key_id: String,
    authorizing_root_generation: u64,
    authorizing_root_revision: u64,
    authorizing_root_lineage_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorityKeyRecord {
    key_id: String,
    purpose: AuthorityKeyPurpose,
    public_key_hex: String,
    public_key_digest: String,
    generation: Option<u64>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    state: AuthorityLifecycleState,
    revision: u64,
    lineage_digest: String,
    delegation: Option<AuthorityDelegation>,
    retired_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    compromised_from: Option<DateTime<Utc>>,
}

impl AuthorityKeyRecord {
    #[cfg(test)]
    fn validate_historical(
        &self,
        authored_at: DateTime<Utc>,
    ) -> Result<(), BrowserRecipeAuthorityError> {
        if authored_at < self.valid_from
            || authored_at >= self.valid_until
            || self.retired_at.is_some_and(|at| authored_at >= at)
            || self.revoked_at.is_some_and(|at| authored_at >= at)
            || self.compromised_from.is_some_and(|at| authored_at >= at)
        {
            return Err(BrowserRecipeAuthorityError::HistoricalKeyInvalid);
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_observed_state(
        &self,
        snapshot_as_of: DateTime<Utc>,
    ) -> Result<(), BrowserRecipeAuthorityError> {
        if self
            .revoked_at
            .is_some_and(|revoked| snapshot_as_of >= revoked)
            || self.compromised_from.is_some()
        {
            return Err(BrowserRecipeAuthorityError::ObservedKeyBlocked);
        }
        Ok(())
    }

    fn state_digest(&self) -> Result<String, BrowserRecipeAuthorityError> {
        digest_json(&(
            "hartevo-browser-recipe-authority-key-state/v1",
            &self.key_id,
            self.purpose,
            &self.public_key_digest,
            self.generation,
            self.valid_from,
            self.valid_until,
            self.state,
            self.revision,
            &self.lineage_digest,
            &self.delegation,
            self.retired_at,
            self.revoked_at,
            self.compromised_from,
        ))
    }
}

impl Serialize for AuthorityDelegation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (
            &self.authorization_digest,
            &self.operation_digest,
            &self.authorizing_root_key_id,
            self.authorizing_root_generation,
            self.authorizing_root_revision,
            &self.authorizing_root_lineage_digest,
        )
            .serialize(serializer)
    }
}

#[derive(Debug)]
struct ReplayedAuthoritySnapshot {
    tenant_id: TenantId,
    project_id: ProjectId,
    snapshot_revision: u64,
    snapshot_as_of: DateTime<Utc>,
    snapshot_digest: String,
    active_root_key_id: Option<String>,
    keys: BTreeMap<String, AuthorityKeyRecord>,
}

impl ReplayedAuthoritySnapshot {
    fn replay(
        snapshot: &BrowserRecipeAuthoritySnapshot,
        validation_at: DateTime<Utc>,
        expectation: &BrowserRecipeAuthoritySnapshotExpectation,
    ) -> Result<Self, BrowserRecipeAuthorityError> {
        if snapshot.schema_version != AUTHORITY_SNAPSHOT_SCHEMA_VERSION
            || snapshot.snapshot_revision == 0
            || snapshot.snapshot_revision
                != u64::try_from(snapshot.mutations.len())
                    .map_err(|_| BrowserRecipeAuthorityError::CounterOverflow)?
            || snapshot.snapshot_as_of > validation_at
            || expectation.tenant_id != snapshot.tenant_id
            || expectation.project_id != snapshot.project_id
            || expectation.snapshot_revision != snapshot.snapshot_revision
            || expectation.snapshot_as_of != snapshot.snapshot_as_of
            || expectation.snapshot_digest != snapshot.digest()?
        {
            return Err(BrowserRecipeAuthorityError::SnapshotExpectationMismatch);
        }
        let mut state = Self {
            tenant_id: snapshot.tenant_id.clone(),
            project_id: snapshot.project_id.clone(),
            snapshot_revision: snapshot.snapshot_revision,
            snapshot_as_of: snapshot.snapshot_as_of,
            snapshot_digest: snapshot.digest()?,
            active_root_key_id: None,
            keys: BTreeMap::new(),
        };
        let mut mutation_ids = BTreeSet::new();
        let mut public_key_digests = BTreeSet::new();
        let mut previous_recorded_at = None;
        for (index, mutation) in snapshot.mutations.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .map_err(|_| BrowserRecipeAuthorityError::CounterOverflow)?
                .checked_add(1)
                .ok_or(BrowserRecipeAuthorityError::CounterOverflow)?;
            if mutation.tenant_id != snapshot.tenant_id
                || mutation.project_id != snapshot.project_id
                || mutation.sequence != expected_sequence
                || mutation.recorded_at > snapshot.snapshot_as_of
                || previous_recorded_at.is_some_and(|previous| mutation.recorded_at < previous)
                || !mutation_ids.insert(mutation.mutation_id.clone())
            {
                return Err(BrowserRecipeAuthorityError::InvalidMutationSequence);
            }
            previous_recorded_at = Some(mutation.recorded_at);
            mutation.validate_binding()?;
            state.apply(mutation, &mut public_key_digests)?;
        }
        Ok(state)
    }

    #[allow(clippy::too_many_lines)]
    fn apply(
        &mut self,
        mutation: &BrowserRecipeAuthorityMutation,
        public_key_digests: &mut BTreeSet<String>,
    ) -> Result<(), BrowserRecipeAuthorityError> {
        let operation_digest = mutation.operation_digest()?;
        match (&mutation.operation, &mutation.signatures) {
            (
                AuthorityOperation::ProvisionRoot {
                    target,
                    generation,
                    public_key_hex,
                    valid_from,
                    valid_until,
                },
                AuthoritySignatureBundle::ProvisionRoot {
                    root_self_possession_hex,
                },
            ) => {
                if !self.keys.is_empty() || self.active_root_key_id.is_some() || *generation != 1 {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                target.validate()?;
                let public_key_digest = canonical_public_key_digest(public_key_hex)?;
                ensure_new_key(
                    &self.keys,
                    public_key_digests,
                    &target.root_key_id,
                    &public_key_digest,
                    *valid_from,
                    *valid_until,
                    mutation.recorded_at,
                )?;
                verify_possession(
                    ROOT_POSSESSION_DOMAIN,
                    &mutation.tenant_id,
                    &mutation.project_id,
                    &operation_digest,
                    &target.root_key_id,
                    AuthorityKeyPurpose::RootAuthority,
                    &public_key_digest,
                    *valid_from,
                    *valid_until,
                    public_key_hex,
                    root_self_possession_hex,
                )?;
                let lineage_digest = digest_json(&(
                    "hartevo-browser-recipe-root-lineage/v1",
                    &operation_digest,
                    &target.root_key_id,
                    generation,
                    &public_key_digest,
                ))?;
                let key = AuthorityKeyRecord {
                    key_id: target.root_key_id.clone(),
                    purpose: AuthorityKeyPurpose::RootAuthority,
                    public_key_hex: public_key_hex.clone(),
                    public_key_digest: public_key_digest.clone(),
                    generation: Some(*generation),
                    valid_from: *valid_from,
                    valid_until: *valid_until,
                    state: AuthorityLifecycleState::Active,
                    revision: KEY_REVISION_INITIAL,
                    lineage_digest,
                    delegation: None,
                    retired_at: None,
                    revoked_at: None,
                    compromised_from: None,
                };
                self.keys.insert(target.root_key_id.clone(), key);
                public_key_digests.insert(public_key_digest);
                self.active_root_key_id = Some(target.root_key_id.clone());
            }
            (
                AuthorityOperation::RotateRoot {
                    target,
                    successor_generation,
                    successor_public_key_hex,
                    successor_valid_from,
                    successor_valid_until,
                },
                AuthoritySignatureBundle::RotateRoot {
                    predecessor_root_authorization_hex,
                    successor_root_possession_hex,
                },
            ) => {
                target.predecessor.validate()?;
                target.successor.validate()?;
                if self.active_root_key_id.as_deref() != Some(target.predecessor.key_id.as_str()) {
                    return Err(BrowserRecipeAuthorityError::InvalidRootHead);
                }
                let predecessor = exact_key(
                    &self.keys,
                    &target.predecessor,
                    AuthorityKeyPurpose::RootAuthority,
                )?
                .clone();
                let expected_generation = predecessor
                    .generation
                    .ok_or(BrowserRecipeAuthorityError::InvalidRootHead)?
                    .checked_add(1)
                    .ok_or(BrowserRecipeAuthorityError::CounterOverflow)?;
                if predecessor.state != AuthorityLifecycleState::Active
                    || *successor_generation != expected_generation
                {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                verify_authorization(
                    mutation.operation.kind().domain(),
                    &mutation.tenant_id,
                    &mutation.project_id,
                    &operation_digest,
                    &predecessor.public_key_hex,
                    predecessor_root_authorization_hex,
                )?;
                let public_key_digest = canonical_public_key_digest(successor_public_key_hex)?;
                ensure_new_key(
                    &self.keys,
                    public_key_digests,
                    &target.successor.root_key_id,
                    &public_key_digest,
                    *successor_valid_from,
                    *successor_valid_until,
                    mutation.recorded_at,
                )?;
                verify_possession(
                    ROOT_POSSESSION_DOMAIN,
                    &mutation.tenant_id,
                    &mutation.project_id,
                    &operation_digest,
                    &target.successor.root_key_id,
                    AuthorityKeyPurpose::RootAuthority,
                    &public_key_digest,
                    *successor_valid_from,
                    *successor_valid_until,
                    successor_public_key_hex,
                    successor_root_possession_hex,
                )?;
                let successor_lineage = digest_json(&(
                    "hartevo-browser-recipe-root-lineage/v1",
                    &predecessor.lineage_digest,
                    &operation_digest,
                    &target.successor.root_key_id,
                    successor_generation,
                    &public_key_digest,
                ))?;
                let predecessor_mut = self
                    .keys
                    .get_mut(&target.predecessor.key_id)
                    .ok_or(BrowserRecipeAuthorityError::UnknownKey)?;
                predecessor_mut.state = AuthorityLifecycleState::Retired;
                predecessor_mut.retired_at = Some(mutation.recorded_at);
                predecessor_mut.revision = next_revision(predecessor_mut.revision)?;
                self.keys.insert(
                    target.successor.root_key_id.clone(),
                    AuthorityKeyRecord {
                        key_id: target.successor.root_key_id.clone(),
                        purpose: AuthorityKeyPurpose::RootAuthority,
                        public_key_hex: successor_public_key_hex.clone(),
                        public_key_digest: public_key_digest.clone(),
                        generation: Some(*successor_generation),
                        valid_from: *successor_valid_from,
                        valid_until: *successor_valid_until,
                        state: AuthorityLifecycleState::Active,
                        revision: KEY_REVISION_INITIAL,
                        lineage_digest: successor_lineage,
                        delegation: None,
                        retired_at: None,
                        revoked_at: None,
                        compromised_from: None,
                    },
                );
                public_key_digests.insert(public_key_digest);
                self.active_root_key_id = Some(target.successor.root_key_id.clone());
            }
            (
                AuthorityOperation::AuthorizeLeaf {
                    authorizing_root,
                    target,
                    public_key_hex,
                    valid_from,
                    valid_until,
                },
                AuthoritySignatureBundle::AuthorizeLeaf {
                    current_root_authorization_hex,
                    new_leaf_possession_hex,
                },
            ) => self.authorize_leaf(
                mutation,
                &operation_digest,
                authorizing_root,
                target,
                public_key_hex,
                *valid_from,
                *valid_until,
                current_root_authorization_hex,
                new_leaf_possession_hex,
                public_key_digests,
            )?,
            (
                AuthorityOperation::RotateLeaf {
                    authorizing_root,
                    target,
                    successor_public_key_hex,
                    successor_valid_from,
                    successor_valid_until,
                },
                AuthoritySignatureBundle::RotateLeaf {
                    current_root_authorization_hex,
                    new_leaf_possession_hex,
                },
            ) => {
                let predecessor =
                    exact_key(&self.keys, &target.predecessor, target.successor.purpose)?;
                if predecessor.state != AuthorityLifecycleState::Active
                    || predecessor.purpose != target.successor.purpose
                {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                self.authorize_leaf(
                    mutation,
                    &operation_digest,
                    authorizing_root,
                    &target.successor,
                    successor_public_key_hex,
                    *successor_valid_from,
                    *successor_valid_until,
                    current_root_authorization_hex,
                    new_leaf_possession_hex,
                    public_key_digests,
                )?;
                let predecessor_mut = self
                    .keys
                    .get_mut(&target.predecessor.key_id)
                    .ok_or(BrowserRecipeAuthorityError::UnknownKey)?;
                predecessor_mut.state = AuthorityLifecycleState::Retired;
                predecessor_mut.retired_at = Some(mutation.recorded_at);
                predecessor_mut.revision = next_revision(predecessor_mut.revision)?;
            }
            (
                AuthorityOperation::RetireKey {
                    authorizing_root,
                    target,
                },
                AuthoritySignatureBundle::RetireKey {
                    current_root_authorization_hex,
                },
            ) => {
                self.verify_current_root(
                    mutation,
                    authorizing_root,
                    &operation_digest,
                    current_root_authorization_hex,
                )?;
                if self.active_root_key_id.as_deref() == Some(target.key_id.as_str()) {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                let key = exact_key_mut(&mut self.keys, target)?;
                if key.state != AuthorityLifecycleState::Active {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                key.state = AuthorityLifecycleState::Retired;
                key.retired_at = Some(mutation.recorded_at);
                key.revision = next_revision(key.revision)?;
            }
            (
                AuthorityOperation::RevokeKey {
                    authorizing_root,
                    target,
                },
                AuthoritySignatureBundle::RevokeKey {
                    current_root_authorization_hex,
                },
            ) => {
                self.verify_current_root(
                    mutation,
                    authorizing_root,
                    &operation_digest,
                    current_root_authorization_hex,
                )?;
                if self.active_root_key_id.as_deref() == Some(target.key_id.as_str()) {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                let key = exact_key_mut(&mut self.keys, target)?;
                if !matches!(
                    key.state,
                    AuthorityLifecycleState::Active | AuthorityLifecycleState::Retired
                ) || mutation.recorded_at < key.valid_from
                    || mutation.recorded_at >= key.valid_until
                {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                key.state = AuthorityLifecycleState::Revoked;
                key.revoked_at = Some(mutation.recorded_at);
                key.revision = next_revision(key.revision)?;
            }
            (
                AuthorityOperation::RecordCompromise {
                    target,
                    compromised_from,
                },
                AuthoritySignatureBundle::RecordCompromise {},
            ) => {
                let key = exact_key_mut(&mut self.keys, target)?;
                if matches!(key.state, AuthorityLifecycleState::Compromised)
                    || *compromised_from < key.valid_from
                    || *compromised_from > mutation.recorded_at
                    || mutation.recorded_at >= key.valid_until
                {
                    return Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition);
                }
                key.state = AuthorityLifecycleState::Compromised;
                key.compromised_from = Some(*compromised_from);
                key.revision = next_revision(key.revision)?;
                if self.active_root_key_id.as_deref() == Some(target.key_id.as_str()) {
                    self.active_root_key_id = None;
                }
            }
            _ => return Err(BrowserRecipeAuthorityError::InvalidSignatureBindings),
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_leaf(
        &mut self,
        mutation: &BrowserRecipeAuthorityMutation,
        operation_digest: &str,
        authorizing_root: &ExistingKeyTarget,
        target: &NewLeafTarget,
        public_key_hex: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        root_signature_hex: &str,
        leaf_possession_hex: &str,
        public_key_digests: &mut BTreeSet<String>,
    ) -> Result<(), BrowserRecipeAuthorityError> {
        target.validate()?;
        self.verify_current_root(
            mutation,
            authorizing_root,
            operation_digest,
            root_signature_hex,
        )?;
        let root = exact_key(
            &self.keys,
            authorizing_root,
            AuthorityKeyPurpose::RootAuthority,
        )?
        .clone();
        let public_key_digest = canonical_public_key_digest(public_key_hex)?;
        ensure_new_key(
            &self.keys,
            public_key_digests,
            &target.leaf_key_id,
            &public_key_digest,
            valid_from,
            valid_until,
            mutation.recorded_at,
        )?;
        verify_possession(
            LEAF_POSSESSION_DOMAIN,
            &mutation.tenant_id,
            &mutation.project_id,
            operation_digest,
            &target.leaf_key_id,
            target.purpose,
            &public_key_digest,
            valid_from,
            valid_until,
            public_key_hex,
            leaf_possession_hex,
        )?;
        let root_generation = root
            .generation
            .ok_or(BrowserRecipeAuthorityError::InvalidRootHead)?;
        let authorization_digest = digest_json(&(
            LEAF_AUTHORIZATION_DOMAIN,
            &mutation.tenant_id,
            &mutation.project_id,
            operation_digest,
            &target.leaf_key_id,
            target.purpose,
            &public_key_digest,
            &root.key_id,
            root_generation,
            root.revision,
            &root.lineage_digest,
        ))?;
        let lineage_digest = digest_json(&(
            "hartevo-browser-recipe-leaf-lineage/v1",
            &authorization_digest,
            &root.lineage_digest,
            operation_digest,
        ))?;
        self.keys.insert(
            target.leaf_key_id.clone(),
            AuthorityKeyRecord {
                key_id: target.leaf_key_id.clone(),
                purpose: target.purpose,
                public_key_hex: public_key_hex.to_owned(),
                public_key_digest: public_key_digest.clone(),
                generation: None,
                valid_from,
                valid_until,
                state: AuthorityLifecycleState::Active,
                revision: KEY_REVISION_INITIAL,
                lineage_digest,
                delegation: Some(AuthorityDelegation {
                    authorization_digest,
                    operation_digest: operation_digest.to_owned(),
                    authorizing_root_key_id: root.key_id,
                    authorizing_root_generation: root_generation,
                    authorizing_root_revision: root.revision,
                    authorizing_root_lineage_digest: root.lineage_digest,
                }),
                retired_at: None,
                revoked_at: None,
                compromised_from: None,
            },
        );
        public_key_digests.insert(public_key_digest);
        Ok(())
    }

    fn verify_current_root(
        &self,
        mutation: &BrowserRecipeAuthorityMutation,
        authorizing_root: &ExistingKeyTarget,
        operation_digest: &str,
        signature_hex: &str,
    ) -> Result<(), BrowserRecipeAuthorityError> {
        authorizing_root.validate()?;
        if self.active_root_key_id.as_deref() != Some(authorizing_root.key_id.as_str()) {
            return Err(BrowserRecipeAuthorityError::InvalidRootHead);
        }
        let root = exact_key(
            &self.keys,
            authorizing_root,
            AuthorityKeyPurpose::RootAuthority,
        )?;
        if root.state != AuthorityLifecycleState::Active
            || mutation.recorded_at < root.valid_from
            || mutation.recorded_at >= root.valid_until
        {
            return Err(BrowserRecipeAuthorityError::InvalidRootHead);
        }
        verify_authorization(
            mutation.operation.kind().domain(),
            &mutation.tenant_id,
            &mutation.project_id,
            operation_digest,
            &root.public_key_hex,
            signature_hex,
        )
    }

    #[cfg(test)]
    fn validate_legacy_leaf(
        &self,
        legacy: &TrustedBrowserRecipeKey,
        authored_at: DateTime<Utc>,
    ) -> Result<(), BrowserRecipeAuthorityError> {
        let rooted = self
            .keys
            .get(&legacy.id)
            .ok_or(BrowserRecipeAuthorityError::UnknownKey)?;
        let legacy_public_digest = canonical_public_key_digest(&legacy.public_key_hex)?;
        if rooted.purpose != AuthorityKeyPurpose::from(legacy.purpose)
            || rooted.public_key_hex != legacy.public_key_hex
            || rooted.public_key_digest != legacy_public_digest
            || rooted.valid_from != legacy.valid_from
            || rooted.valid_until != legacy.valid_until
        {
            return Err(BrowserRecipeAuthorityError::LegacyTrustMismatch);
        }
        rooted.validate_historical(authored_at)?;
        rooted.validate_observed_state(self.snapshot_as_of)?;
        if legacy
            .revoked_at
            .is_some_and(|revoked| self.snapshot_as_of >= revoked)
        {
            return Err(BrowserRecipeAuthorityError::ObservedKeyBlocked);
        }
        let delegation = rooted
            .delegation
            .as_ref()
            .ok_or(BrowserRecipeAuthorityError::DelegationMismatch)?;
        let root = self
            .keys
            .get(&delegation.authorizing_root_key_id)
            .ok_or(BrowserRecipeAuthorityError::DelegationMismatch)?;
        if root.generation != Some(delegation.authorizing_root_generation)
            || root.lineage_digest != delegation.authorizing_root_lineage_digest
            || root.revision < delegation.authorizing_root_revision
        {
            return Err(BrowserRecipeAuthorityError::DelegationMismatch);
        }
        let expected_authorization_digest = digest_json(&(
            LEAF_AUTHORIZATION_DOMAIN,
            &self.tenant_id,
            &self.project_id,
            &delegation.operation_digest,
            &rooted.key_id,
            rooted.purpose,
            &rooted.public_key_digest,
            &root.key_id,
            delegation.authorizing_root_generation,
            delegation.authorizing_root_revision,
            &delegation.authorizing_root_lineage_digest,
        ))?;
        let expected_lineage_digest = digest_json(&(
            "hartevo-browser-recipe-leaf-lineage/v1",
            &expected_authorization_digest,
            &delegation.authorizing_root_lineage_digest,
            &delegation.operation_digest,
        ))?;
        if delegation.authorization_digest != expected_authorization_digest
            || rooted.lineage_digest != expected_lineage_digest
        {
            return Err(BrowserRecipeAuthorityError::DelegationMismatch);
        }
        root.validate_observed_state(self.snapshot_as_of)
    }

    fn state_digest(&self) -> Result<String, BrowserRecipeAuthorityError> {
        let key_digests = self
            .keys
            .values()
            .map(AuthorityKeyRecord::state_digest)
            .collect::<Result<Vec<_>, _>>()?;
        digest_json(&(
            "hartevo-browser-recipe-authority-replayed-state/v1",
            &self.tenant_id,
            &self.project_id,
            self.snapshot_revision,
            self.snapshot_as_of,
            &self.snapshot_digest,
            &self.active_root_key_id,
            key_digests,
        ))
    }
}

fn validate_supplied_authority_snapshot(
    snapshot: &BrowserRecipeAuthoritySnapshot,
    expectation: &BrowserRecipeAuthoritySnapshotExpectation,
    validation_at: DateTime<Utc>,
) -> Result<SnapshotValidatedAuthorization, BrowserRecipeAuthorityError> {
    let replayed = ReplayedAuthoritySnapshot::replay(snapshot, validation_at, expectation)?;
    Ok(SnapshotValidatedAuthorization {
        tenant_id: replayed.tenant_id.clone(),
        project_id: replayed.project_id.clone(),
        snapshot_revision: replayed.snapshot_revision,
        snapshot_as_of: replayed.snapshot_as_of,
        snapshot_digest: replayed.snapshot_digest.clone(),
        state_digest: replayed.state_digest()?,
        snapshot_freshness_authority: false,
        production_dispatch: false,
    })
}

/// Production entry point: validate the checked contract and supplied snapshot,
/// then deny because the checked human-operation and issuer registries are empty.
pub(super) fn validate_supplied_authority_snapshot_json(
    snapshot_json: &str,
    expected_tenant_id: &TenantId,
    expected_project_id: &ProjectId,
    expected_snapshot_revision: u64,
    expected_snapshot_as_of: DateTime<Utc>,
    expected_snapshot_digest: &str,
    validation_at: DateTime<Utc>,
) -> Result<(), BrowserRecipeAuthorityError> {
    let contract = BrowserRecipeAuthorityContract::baseline()?;
    let snapshot = serde_json::from_str::<BrowserRecipeAuthoritySnapshot>(snapshot_json)
        .map_err(|_| BrowserRecipeAuthorityError::InvalidMutation)?;
    let expectation = BrowserRecipeAuthoritySnapshotExpectation {
        tenant_id: expected_tenant_id.clone(),
        project_id: expected_project_id.clone(),
        snapshot_revision: expected_snapshot_revision,
        snapshot_as_of: expected_snapshot_as_of,
        snapshot_digest: expected_snapshot_digest.to_owned(),
    };
    let _ = validate_supplied_authority_snapshot(&snapshot, &expectation, validation_at)?;
    contract.deny_unregistered_admission()
}

fn exact_key<'a>(
    keys: &'a BTreeMap<String, AuthorityKeyRecord>,
    target: &ExistingKeyTarget,
    expected_purpose: AuthorityKeyPurpose,
) -> Result<&'a AuthorityKeyRecord, BrowserRecipeAuthorityError> {
    target.validate()?;
    let key = keys
        .get(&target.key_id)
        .ok_or(BrowserRecipeAuthorityError::UnknownKey)?;
    if key.revision != target.expected_revision || key.purpose != expected_purpose {
        return Err(BrowserRecipeAuthorityError::RevisionOrPurposeMismatch);
    }
    Ok(key)
}

fn exact_key_mut<'a>(
    keys: &'a mut BTreeMap<String, AuthorityKeyRecord>,
    target: &ExistingKeyTarget,
) -> Result<&'a mut AuthorityKeyRecord, BrowserRecipeAuthorityError> {
    target.validate()?;
    let key = keys
        .get_mut(&target.key_id)
        .ok_or(BrowserRecipeAuthorityError::UnknownKey)?;
    if key.revision != target.expected_revision {
        return Err(BrowserRecipeAuthorityError::RevisionOrPurposeMismatch);
    }
    Ok(key)
}

fn ensure_new_key(
    keys: &BTreeMap<String, AuthorityKeyRecord>,
    public_key_digests: &BTreeSet<String>,
    key_id: &str,
    public_key_digest: &str,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
) -> Result<(), BrowserRecipeAuthorityError> {
    if !valid_id(key_id)
        || keys.contains_key(key_id)
        || public_key_digests.contains(public_key_digest)
        || valid_until <= valid_from
        || recorded_at < valid_from
        || recorded_at >= valid_until
    {
        return Err(BrowserRecipeAuthorityError::DuplicateOrInvalidKey);
    }
    Ok(())
}

fn canonical_public_key_digest(value: &str) -> Result<String, BrowserRecipeAuthorityError> {
    let decoded = hex::decode(value).map_err(|_| BrowserRecipeAuthorityError::InvalidPublicKey)?;
    if decoded.len() != ED25519_PUBLIC_KEY_BYTES || value != hex::encode(&decoded) {
        return Err(BrowserRecipeAuthorityError::InvalidPublicKey);
    }
    Ok(format!("{:x}", Sha256::digest(decoded)))
}

#[allow(clippy::too_many_arguments)]
fn verify_possession(
    domain: &'static str,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    operation_digest: &str,
    key_id: &str,
    purpose: AuthorityKeyPurpose,
    public_key_digest: &str,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<(), BrowserRecipeAuthorityError> {
    let payload = serde_json::to_vec(&(
        domain,
        tenant_id,
        project_id,
        operation_digest,
        key_id,
        purpose,
        public_key_digest,
        valid_from,
        valid_until,
    ))
    .map_err(|_| BrowserRecipeAuthorityError::CanonicalEncoding)?;
    verify_ed25519(public_key_hex, signature_hex, &payload)
}

fn verify_authorization(
    domain: &'static str,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    operation_digest: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<(), BrowserRecipeAuthorityError> {
    let payload = serde_json::to_vec(&(domain, tenant_id, project_id, operation_digest))
        .map_err(|_| BrowserRecipeAuthorityError::CanonicalEncoding)?;
    verify_ed25519(public_key_hex, signature_hex, &payload)
}

fn verify_ed25519(
    public_key_hex: &str,
    signature_hex: &str,
    payload: &[u8],
) -> Result<(), BrowserRecipeAuthorityError> {
    let public_key =
        hex::decode(public_key_hex).map_err(|_| BrowserRecipeAuthorityError::InvalidPublicKey)?;
    let signature =
        hex::decode(signature_hex).map_err(|_| BrowserRecipeAuthorityError::InvalidSignature)?;
    if public_key.len() != ED25519_PUBLIC_KEY_BYTES
        || signature.len() != ED25519_SIGNATURE_BYTES
        || public_key_hex != hex::encode(&public_key)
        || signature_hex != hex::encode(&signature)
    {
        return Err(BrowserRecipeAuthorityError::InvalidSignature);
    }
    UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(payload, &signature)
        .map_err(|_| BrowserRecipeAuthorityError::InvalidSignature)
}

fn digest_json(value: &impl Serialize) -> Result<String, BrowserRecipeAuthorityError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| BrowserRecipeAuthorityError::CanonicalEncoding)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
    is_bounded_identifier(value)
}

fn next_revision(value: u64) -> Result<u64, BrowserRecipeAuthorityError> {
    value
        .checked_add(1)
        .ok_or(BrowserRecipeAuthorityError::CounterOverflow)
}

fn validate_exact_set<T: Ord>(
    actual: &[T],
    expected: &[T],
    label: &'static str,
) -> Result<(), BrowserRecipeAuthorityError> {
    let actual_set = actual.iter().collect::<BTreeSet<_>>();
    let expected_set = expected.iter().collect::<BTreeSet<_>>();
    if actual_set.len() != actual.len() {
        return Err(BrowserRecipeAuthorityError::DuplicateContractValue(label));
    }
    if actual_set != expected_set {
        return Err(BrowserRecipeAuthorityError::ContractSetMismatch(label));
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(super) enum BrowserRecipeAuthorityError {
    #[error("Recipe authority contract JSON is malformed, incomplete, duplicated, or unknown")]
    InvalidContractDocument,
    #[error("Recipe authority contract grants unsupported authority")]
    InvalidAuthorityBoundary,
    #[error("Recipe authority contract contains duplicate {0}")]
    DuplicateContractValue(&'static str),
    #[error("Recipe authority contract does not declare the exact {0} set")]
    ContractSetMismatch(&'static str),
    #[error("Recipe authority digest domains do not match the implementation")]
    InvalidDigestDomains,
    #[error("Recipe authority target bindings do not match the lifecycle state machine")]
    InvalidTargetBindings,
    #[error("Recipe authority signature bindings do not match the lifecycle state machine")]
    InvalidSignatureBindings,
    #[error("Recipe lifecycle admission is denied by the empty checked registries")]
    LifecycleAdmissionDenied,
    #[error("Recipe authority snapshot does not match the exact expected identity")]
    SnapshotExpectationMismatch,
    #[error("Recipe authority mutation sequence is invalid or rolled back")]
    InvalidMutationSequence,
    #[error("Recipe authority mutation is malformed")]
    InvalidMutation,
    #[error("Recipe authority mutation target is malformed or mismatched")]
    InvalidMutationTarget,
    #[error("Recipe lifecycle human authority binding is malformed or cross-domain")]
    InvalidLifecycleAuthority,
    #[error("Recipe authority lifecycle transition is invalid")]
    InvalidLifecycleTransition,
    #[error("Recipe authority root head is stale, retired, or replaced")]
    InvalidRootHead,
    #[error("Recipe authority key is missing")]
    UnknownKey,
    #[error("Recipe authority key revision or purpose does not match")]
    RevisionOrPurposeMismatch,
    #[error("Recipe authority key id, public key, or validity window is duplicate or invalid")]
    DuplicateOrInvalidKey,
    #[error("Recipe authority Ed25519 public key is non-canonical")]
    InvalidPublicKey,
    #[error("Recipe authority Ed25519 signature is invalid")]
    InvalidSignature,
    #[error("Recipe authority canonical encoding failed")]
    CanonicalEncoding,
    #[error("Recipe authority counter overflowed")]
    CounterOverflow,
    #[cfg(test)]
    #[error("Recipe artifact was not historically valid under the signing key")]
    HistoricalKeyInvalid,
    #[cfg(test)]
    #[error("Recipe signing ancestry is revoked or compromised in the supplied snapshot")]
    ObservedKeyBlocked,
    #[cfg(test)]
    #[error("Legacy Recipe trust does not exactly match rooted leaf authorization")]
    LegacyTrustMismatch,
    #[cfg(test)]
    #[error("Recipe leaf delegation ancestry is missing or inconsistent")]
    DelegationMismatch,
}

#[cfg(test)]
#[path = "real_chromium_recipe_negative_lifecycle_test.rs"]
mod real_chromium_recipe_negative_lifecycle_test;

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::{Value, json};

    use super::*;

    struct SigningFixture {
        root_one: Ed25519KeyPair,
        root_two: Ed25519KeyPair,
        candidate_one: Ed25519KeyPair,
        candidate_two: Ed25519KeyPair,
        release_one: Ed25519KeyPair,
    }

    impl SigningFixture {
        fn new() -> Self {
            Self {
                root_one: signing_key(1),
                root_two: signing_key(2),
                candidate_one: signing_key(3),
                candidate_two: signing_key(4),
                release_one: signing_key(5),
            }
        }
    }

    fn signing_key(seed: u8) -> Ed25519KeyPair {
        // Fixed seeds are test fixtures only and never enter production code.
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("test signing key")
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("time")
    }

    fn tenant() -> TenantId {
        TenantId::from("tenant-recipe-authority")
    }

    fn project() -> ProjectId {
        ProjectId::from("project-recipe-authority")
    }

    fn public_key_hex(key: &Ed25519KeyPair) -> String {
        hex::encode(key.public_key().as_ref())
    }

    fn synthetic_human_reference() -> HumanOperationAuthorityReference {
        HumanOperationAuthorityReference {
            schema_version: "hartevo-human-operation-authority-contract/test-only-v1".into(),
            contract_version: "test-only-recipe-root-lifecycle/v1".into(),
            contract_digest: format!("{:x}", Sha256::digest(b"test-only-human-contract")),
            operation_kinds: vec!["recipe_root_lifecycle".into()],
        }
    }

    fn current_a3_reference(operation_kind: &str) -> HumanOperationAuthorityReference {
        HumanOperationAuthorityReference {
            schema_version: CURRENT_A3_HUMAN_SCHEMA.into(),
            contract_version: CURRENT_A3_HUMAN_VERSION.into(),
            contract_digest: CURRENT_A3_HUMAN_DIGEST.into(),
            operation_kinds: vec![operation_kind.into()],
        }
    }

    fn mutation(
        sequence: u64,
        recorded_at: DateTime<Utc>,
        operation: AuthorityOperation,
        signatures: impl FnOnce(&str) -> AuthoritySignatureBundle,
    ) -> BrowserRecipeAuthorityMutation {
        let kind = operation.kind();
        let target = operation.target();
        let mut mutation = BrowserRecipeAuthorityMutation {
            schema_version: AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
            tenant_id: tenant(),
            project_id: project(),
            mutation_id: format!("recipe-authority-mutation-{sequence}"),
            sequence,
            recorded_at,
            operation,
            lifecycle_authority: LifecycleAuthorityBinding {
                human_operation_authority: synthetic_human_reference(),
                authority_kind: LifecycleAuthorityKind::RecipeRootLifecycle,
                decision: LifecycleDecision::Approve,
                operation_kind: kind,
                tenant_id: tenant(),
                project_id: project(),
                target,
                issued_at: recorded_at - Duration::minutes(1),
                valid_until: recorded_at + Duration::minutes(5),
                operation_digest: String::new(),
                capability_digest: format!(
                    "{:x}",
                    Sha256::digest(b"browser.recipe.root.lifecycle")
                ),
                authority_digest: String::new(),
            },
            signatures: AuthoritySignatureBundle::RecordCompromise {},
        };
        let operation_digest = mutation.operation_digest().expect("operation digest");
        mutation.lifecycle_authority.operation_digest = operation_digest.clone();
        mutation.lifecycle_authority.authority_digest = mutation
            .lifecycle_authority
            .canonical_digest()
            .expect("authority digest");
        mutation.signatures = signatures(&operation_digest);
        mutation
    }

    fn authorization_signature(
        key: &Ed25519KeyPair,
        kind: AuthorityMutationKind,
        operation_digest: &str,
    ) -> String {
        let payload = serde_json::to_vec(&(kind.domain(), tenant(), project(), operation_digest))
            .expect("authorization payload");
        hex::encode(key.sign(&payload).as_ref())
    }

    #[allow(clippy::too_many_arguments)]
    fn possession_signature(
        key: &Ed25519KeyPair,
        domain: &'static str,
        operation_digest: &str,
        key_id: &str,
        purpose: AuthorityKeyPurpose,
        public_key_digest: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> String {
        let payload = serde_json::to_vec(&(
            domain,
            tenant(),
            project(),
            operation_digest,
            key_id,
            purpose,
            public_key_digest,
            valid_from,
            valid_until,
        ))
        .expect("possession payload");
        hex::encode(key.sign(&payload).as_ref())
    }

    fn provision_root(
        sequence: u64,
        at: DateTime<Utc>,
        key_id: &str,
        generation: u64,
        key: &Ed25519KeyPair,
    ) -> BrowserRecipeAuthorityMutation {
        let valid_from = at - Duration::minutes(1);
        let valid_until = at + Duration::days(30);
        let public_key_hex = public_key_hex(key);
        let public_key_digest =
            canonical_public_key_digest(&public_key_hex).expect("public digest");
        mutation(
            sequence,
            at,
            AuthorityOperation::ProvisionRoot {
                target: NewRootTarget {
                    root_key_id: key_id.into(),
                    expected_absent: true,
                },
                generation,
                public_key_hex,
                valid_from,
                valid_until,
            },
            |operation_digest| AuthoritySignatureBundle::ProvisionRoot {
                root_self_possession_hex: possession_signature(
                    key,
                    ROOT_POSSESSION_DOMAIN,
                    operation_digest,
                    key_id,
                    AuthorityKeyPurpose::RootAuthority,
                    &public_key_digest,
                    valid_from,
                    valid_until,
                ),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rotate_root(
        sequence: u64,
        at: DateTime<Utc>,
        predecessor_id: &str,
        predecessor_revision: u64,
        predecessor: &Ed25519KeyPair,
        successor_id: &str,
        successor_generation: u64,
        successor: &Ed25519KeyPair,
    ) -> BrowserRecipeAuthorityMutation {
        let valid_from = at;
        let valid_until = at + Duration::days(30);
        let successor_public_key_hex = public_key_hex(successor);
        let successor_digest =
            canonical_public_key_digest(&successor_public_key_hex).expect("successor digest");
        mutation(
            sequence,
            at,
            AuthorityOperation::RotateRoot {
                target: RootRotationTargets {
                    predecessor: ExistingKeyTarget {
                        key_id: predecessor_id.into(),
                        expected_revision: predecessor_revision,
                    },
                    successor: NewRootTarget {
                        root_key_id: successor_id.into(),
                        expected_absent: true,
                    },
                },
                successor_generation,
                successor_public_key_hex,
                successor_valid_from: valid_from,
                successor_valid_until: valid_until,
            },
            |operation_digest| AuthoritySignatureBundle::RotateRoot {
                predecessor_root_authorization_hex: authorization_signature(
                    predecessor,
                    AuthorityMutationKind::RotateRoot,
                    operation_digest,
                ),
                successor_root_possession_hex: possession_signature(
                    successor,
                    ROOT_POSSESSION_DOMAIN,
                    operation_digest,
                    successor_id,
                    AuthorityKeyPurpose::RootAuthority,
                    &successor_digest,
                    valid_from,
                    valid_until,
                ),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_leaf(
        sequence: u64,
        at: DateTime<Utc>,
        root_id: &str,
        root_revision: u64,
        root: &Ed25519KeyPair,
        leaf_id: &str,
        purpose: AuthorityKeyPurpose,
        leaf: &Ed25519KeyPair,
    ) -> BrowserRecipeAuthorityMutation {
        let valid_from = at;
        let valid_until = at + Duration::days(20);
        let leaf_public_key_hex = public_key_hex(leaf);
        let leaf_digest =
            canonical_public_key_digest(&leaf_public_key_hex).expect("leaf public digest");
        mutation(
            sequence,
            at,
            AuthorityOperation::AuthorizeLeaf {
                authorizing_root: ExistingKeyTarget {
                    key_id: root_id.into(),
                    expected_revision: root_revision,
                },
                target: NewLeafTarget {
                    leaf_key_id: leaf_id.into(),
                    purpose,
                    expected_absent: true,
                },
                public_key_hex: leaf_public_key_hex,
                valid_from,
                valid_until,
            },
            |operation_digest| AuthoritySignatureBundle::AuthorizeLeaf {
                current_root_authorization_hex: authorization_signature(
                    root,
                    AuthorityMutationKind::AuthorizeLeaf,
                    operation_digest,
                ),
                new_leaf_possession_hex: possession_signature(
                    leaf,
                    LEAF_POSSESSION_DOMAIN,
                    operation_digest,
                    leaf_id,
                    purpose,
                    &leaf_digest,
                    valid_from,
                    valid_until,
                ),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rotate_leaf(
        sequence: u64,
        at: DateTime<Utc>,
        root_id: &str,
        root_revision: u64,
        root: &Ed25519KeyPair,
        predecessor_id: &str,
        predecessor_revision: u64,
        successor_id: &str,
        purpose: AuthorityKeyPurpose,
        successor: &Ed25519KeyPair,
    ) -> BrowserRecipeAuthorityMutation {
        let valid_from = at;
        let valid_until = at + Duration::days(20);
        let successor_public_key_hex = public_key_hex(successor);
        let successor_digest = canonical_public_key_digest(&successor_public_key_hex)
            .expect("successor public digest");
        mutation(
            sequence,
            at,
            AuthorityOperation::RotateLeaf {
                authorizing_root: ExistingKeyTarget {
                    key_id: root_id.into(),
                    expected_revision: root_revision,
                },
                target: LeafRotationTargets {
                    predecessor: ExistingKeyTarget {
                        key_id: predecessor_id.into(),
                        expected_revision: predecessor_revision,
                    },
                    successor: NewLeafTarget {
                        leaf_key_id: successor_id.into(),
                        purpose,
                        expected_absent: true,
                    },
                },
                successor_public_key_hex,
                successor_valid_from: valid_from,
                successor_valid_until: valid_until,
            },
            |operation_digest| AuthoritySignatureBundle::RotateLeaf {
                current_root_authorization_hex: authorization_signature(
                    root,
                    AuthorityMutationKind::RotateLeaf,
                    operation_digest,
                ),
                new_leaf_possession_hex: possession_signature(
                    successor,
                    LEAF_POSSESSION_DOMAIN,
                    operation_digest,
                    successor_id,
                    purpose,
                    &successor_digest,
                    valid_from,
                    valid_until,
                ),
            },
        )
    }

    fn revoke_key(
        sequence: u64,
        at: DateTime<Utc>,
        root_id: &str,
        root_revision: u64,
        root: &Ed25519KeyPair,
        target_id: &str,
        target_revision: u64,
    ) -> BrowserRecipeAuthorityMutation {
        mutation(
            sequence,
            at,
            AuthorityOperation::RevokeKey {
                authorizing_root: ExistingKeyTarget {
                    key_id: root_id.into(),
                    expected_revision: root_revision,
                },
                target: ExistingKeyTarget {
                    key_id: target_id.into(),
                    expected_revision: target_revision,
                },
            },
            |operation_digest| AuthoritySignatureBundle::RevokeKey {
                current_root_authorization_hex: authorization_signature(
                    root,
                    AuthorityMutationKind::RevokeKey,
                    operation_digest,
                ),
            },
        )
    }

    fn compromise_key(
        sequence: u64,
        at: DateTime<Utc>,
        target_id: &str,
        target_revision: u64,
        compromised_from: DateTime<Utc>,
    ) -> BrowserRecipeAuthorityMutation {
        mutation(
            sequence,
            at,
            AuthorityOperation::RecordCompromise {
                target: ExistingKeyTarget {
                    key_id: target_id.into(),
                    expected_revision: target_revision,
                },
                compromised_from,
            },
            |_| AuthoritySignatureBundle::RecordCompromise {},
        )
    }

    fn snapshot(
        mutations: Vec<BrowserRecipeAuthorityMutation>,
        snapshot_as_of: DateTime<Utc>,
    ) -> BrowserRecipeAuthoritySnapshot {
        BrowserRecipeAuthoritySnapshot {
            schema_version: AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
            tenant_id: tenant(),
            project_id: project(),
            snapshot_revision: u64::try_from(mutations.len()).expect("revision"),
            snapshot_as_of,
            mutations,
        }
    }

    fn replay(
        snapshot: &BrowserRecipeAuthoritySnapshot,
        validation_at: DateTime<Utc>,
    ) -> Result<ReplayedAuthoritySnapshot, BrowserRecipeAuthorityError> {
        ReplayedAuthoritySnapshot::replay(
            snapshot,
            validation_at,
            &snapshot.expectation().expect("expectation"),
        )
    }

    fn legacy_leaf(
        key_id: &str,
        purpose: BrowserRecipeKeyPurpose,
        key: &Ed25519KeyPair,
        valid_from: DateTime<Utc>,
    ) -> TrustedBrowserRecipeKey {
        TrustedBrowserRecipeKey::new(
            key_id,
            purpose,
            key.public_key().as_ref(),
            valid_from,
            valid_from + Duration::days(20),
        )
        .expect("legacy leaf")
    }

    #[test]
    fn checked_contract_is_snapshot_only_and_admission_registries_are_empty() {
        let contract = BrowserRecipeAuthorityContract::baseline().expect("checked contract");
        assert_eq!(
            contract.authority,
            SnapshotAuthorityKind::PublicSnapshotValidationOnly
        );
        assert!(!contract.snapshot_freshness_authority);
        assert!(!contract.production_dispatch);
        assert_eq!(contract.permit_candidate_max_ttl_seconds, 60);
        assert!(
            contract
                .accepted_human_operation_authority_references
                .is_empty()
        );
        assert!(contract.lifecycle_admission_registrations.is_empty());
        assert_eq!(
            contract.deny_unregistered_admission(),
            Err(BrowserRecipeAuthorityError::LifecycleAdmissionDenied)
        );
    }

    #[test]
    fn checked_contract_rejects_unknown_missing_duplicate_and_nonexact_sets() {
        let mut unknown = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        unknown
            .as_object_mut()
            .expect("object")
            .insert("unknownField".into(), json!(true));
        assert_eq!(
            BrowserRecipeAuthorityContract::from_json(
                &serde_json::to_string(&unknown).expect("unknown JSON")
            ),
            Err(BrowserRecipeAuthorityError::InvalidContractDocument)
        );

        let mut missing = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        missing
            .as_object_mut()
            .expect("object")
            .remove("signatureBindings");
        assert_eq!(
            BrowserRecipeAuthorityContract::from_json(
                &serde_json::to_string(&missing).expect("missing JSON")
            ),
            Err(BrowserRecipeAuthorityError::InvalidContractDocument)
        );

        let duplicate = CONTRACT_JSON.replacen(
            "{\n",
            "{\n  \"schemaVersion\": \"hartevo-browser-recipe-authority/v1\",\n",
            1,
        );
        assert_eq!(
            BrowserRecipeAuthorityContract::from_json(&duplicate),
            Err(BrowserRecipeAuthorityError::InvalidContractDocument)
        );

        let mut duplicate_set =
            serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        duplicate_set["keyPurposes"]
            .as_array_mut()
            .expect("purposes")
            .push(json!("root_authority"));
        assert!(matches!(
            BrowserRecipeAuthorityContract::from_json(
                &serde_json::to_string(&duplicate_set).expect("duplicate set JSON")
            ),
            Err(BrowserRecipeAuthorityError::DuplicateContractValue(
                "key purposes"
            ))
        ));

        let mut missing_set = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        missing_set["mutationKinds"]
            .as_array_mut()
            .expect("mutations")
            .pop();
        assert!(matches!(
            BrowserRecipeAuthorityContract::from_json(
                &serde_json::to_string(&missing_set).expect("missing set JSON")
            ),
            Err(BrowserRecipeAuthorityError::ContractSetMismatch(
                "mutation kinds"
            ))
        ));
    }

    #[test]
    fn current_a3_human_contract_six_negative_classes_never_admit_lifecycle() {
        let exact_provider = current_a3_reference("approve_provider_effect");
        let relabeled_recipe = current_a3_reference("recipe_root_lifecycle");
        let mut wrong_schema = relabeled_recipe.clone();
        wrong_schema.schema_version = "hartevo-human-operation-authority-contract/v2".into();
        let mut wrong_version = relabeled_recipe.clone();
        wrong_version.contract_version = "human-operation-authority-e1/v2".into();
        let mut wrong_digest = relabeled_recipe.clone();
        wrong_digest.contract_digest = "0".repeat(64);

        for reference in [
            exact_provider,
            relabeled_recipe.clone(),
            wrong_schema,
            wrong_version,
            wrong_digest,
        ] {
            let mut value = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
            value["acceptedHumanOperationAuthorityReferences"] =
                json!([serde_json::to_value(reference).expect("reference")]);
            assert_eq!(
                BrowserRecipeAuthorityContract::from_json(
                    &serde_json::to_string(&value).expect("reference JSON")
                ),
                Err(BrowserRecipeAuthorityError::InvalidAuthorityBoundary)
            );
        }

        let mut registered = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        registered["lifecycleAdmissionRegistrations"] = json!([{
            "authority": "recipe_root_lifecycle",
            "reference": serde_json::to_value(synthetic_human_reference()).expect("reference"),
            "issuerId": "test-only-issuer",
            "issuerVersion": 1
        }]);
        assert_eq!(
            BrowserRecipeAuthorityContract::from_json(
                &serde_json::to_string(&registered).expect("registration JSON")
            ),
            Err(BrowserRecipeAuthorityError::InvalidAuthorityBoundary)
        );

        let keys = SigningFixture::new();
        let at = now();
        let mut wrong_operation = provision_root(1, at, "root-1", 1, &keys.root_one);
        wrong_operation
            .lifecycle_authority
            .human_operation_authority = current_a3_reference("approve_provider_effect");
        wrong_operation.lifecycle_authority.authority_digest = wrong_operation
            .lifecycle_authority
            .canonical_digest()
            .expect("authority digest");
        assert!(matches!(
            replay(&snapshot(vec![wrong_operation], at), at),
            Err(BrowserRecipeAuthorityError::InvalidLifecycleAuthority)
        ));

        let mut relabeled = provision_root(1, at, "root-1", 1, &keys.root_one);
        relabeled.lifecycle_authority.human_operation_authority = relabeled_recipe;
        relabeled.lifecycle_authority.authority_digest = relabeled
            .lifecycle_authority
            .canonical_digest()
            .expect("authority digest");
        let relabeled_snapshot = snapshot(vec![relabeled], at);
        let expectation = relabeled_snapshot.expectation().expect("expectation");
        assert_eq!(
            validate_supplied_authority_snapshot_json(
                &serde_json::to_string(&relabeled_snapshot).expect("snapshot JSON"),
                &expectation.tenant_id,
                &expectation.project_id,
                expectation.snapshot_revision,
                expectation.snapshot_as_of,
                &expectation.snapshot_digest,
                at,
            ),
            Err(BrowserRecipeAuthorityError::LifecycleAdmissionDenied)
        );
    }

    #[test]
    fn production_entry_replays_public_snapshot_then_denies_empty_admission() {
        let keys = SigningFixture::new();
        let at = now();
        let snapshot = snapshot(vec![provision_root(1, at, "root-1", 1, &keys.root_one)], at);
        let expectation = snapshot.expectation().expect("expectation");
        let validated = validate_supplied_authority_snapshot(&snapshot, &expectation, at)
            .expect("supplied snapshot validation");
        assert!(!validated.snapshot_freshness_authority);
        assert!(!validated.production_dispatch);
        assert_eq!(
            validate_supplied_authority_snapshot_json(
                &serde_json::to_string(&snapshot).expect("snapshot JSON"),
                &expectation.tenant_id,
                &expectation.project_id,
                expectation.snapshot_revision,
                expectation.snapshot_as_of,
                &expectation.snapshot_digest,
                at,
            ),
            Err(BrowserRecipeAuthorityError::LifecycleAdmissionDenied)
        );
    }

    #[test]
    fn root_rotation_preserves_historical_leaf_but_stale_root_cannot_mutate() {
        let keys = SigningFixture::new();
        let at = now();
        let mutations = vec![
            provision_root(1, at, "root-1", 1, &keys.root_one),
            authorize_leaf(
                2,
                at + Duration::minutes(1),
                "root-1",
                1,
                &keys.root_one,
                "candidate-1",
                AuthorityKeyPurpose::CandidatePublisher,
                &keys.candidate_one,
            ),
            rotate_root(
                3,
                at + Duration::minutes(2),
                "root-1",
                1,
                &keys.root_one,
                "root-2",
                2,
                &keys.root_two,
            ),
        ];
        let authority = replay(
            &snapshot(mutations.clone(), at + Duration::minutes(3)),
            at + Duration::minutes(3),
        )
        .expect("rotated authority");
        assert_eq!(authority.active_root_key_id.as_deref(), Some("root-2"));
        assert_eq!(
            authority.keys["root-1"].state,
            AuthorityLifecycleState::Retired
        );
        assert_eq!(
            authority.keys["candidate-1"]
                .delegation
                .as_ref()
                .expect("delegation")
                .authorizing_root_key_id,
            "root-1"
        );
        authority
            .validate_legacy_leaf(
                &legacy_leaf(
                    "candidate-1",
                    BrowserRecipeKeyPurpose::CandidatePublisher,
                    &keys.candidate_one,
                    at + Duration::minutes(1),
                ),
                at + Duration::minutes(1),
            )
            .expect("retired root ancestry remains historically provable");

        let stale_mutation = authorize_leaf(
            4,
            at + Duration::minutes(4),
            "root-1",
            2,
            &keys.root_one,
            "release-stale",
            AuthorityKeyPurpose::ProductionRelease,
            &keys.release_one,
        );
        let stale_snapshot = snapshot(
            mutations.into_iter().chain([stale_mutation]).collect(),
            at + Duration::minutes(4),
        );
        assert!(matches!(
            replay(&stale_snapshot, at + Duration::minutes(4)),
            Err(BrowserRecipeAuthorityError::InvalidRootHead)
        ));
    }

    #[test]
    fn leaf_rotation_is_purpose_exact_and_half_open() {
        let keys = SigningFixture::new();
        let at = now();
        let rotated_at = at + Duration::minutes(2);
        let authority = replay(
            &snapshot(
                vec![
                    provision_root(1, at, "root-1", 1, &keys.root_one),
                    authorize_leaf(
                        2,
                        at + Duration::minutes(1),
                        "root-1",
                        1,
                        &keys.root_one,
                        "candidate-1",
                        AuthorityKeyPurpose::CandidatePublisher,
                        &keys.candidate_one,
                    ),
                    rotate_leaf(
                        3,
                        rotated_at,
                        "root-1",
                        1,
                        &keys.root_one,
                        "candidate-1",
                        1,
                        "candidate-2",
                        AuthorityKeyPurpose::CandidatePublisher,
                        &keys.candidate_two,
                    ),
                ],
                at + Duration::minutes(3),
            ),
            at + Duration::minutes(3),
        )
        .expect("leaf rotation");
        assert_eq!(
            authority.keys["candidate-1"].state,
            AuthorityLifecycleState::Retired
        );
        authority.keys["candidate-1"]
            .validate_historical(rotated_at - Duration::seconds(1))
            .expect("pre-retirement artifact remains historical");
        assert_eq!(
            authority.keys["candidate-1"].validate_historical(rotated_at),
            Err(BrowserRecipeAuthorityError::HistoricalKeyInvalid)
        );
        authority
            .validate_legacy_leaf(
                &legacy_leaf(
                    "candidate-2",
                    BrowserRecipeKeyPurpose::CandidatePublisher,
                    &keys.candidate_two,
                    rotated_at,
                ),
                rotated_at,
            )
            .expect("successor active at inclusive validFrom");

        let mut wrong_purpose = rotate_leaf(
            3,
            rotated_at,
            "root-1",
            1,
            &keys.root_one,
            "candidate-1",
            1,
            "release-2",
            AuthorityKeyPurpose::ProductionRelease,
            &keys.release_one,
        );
        if let AuthorityOperation::RotateLeaf { target, .. } = &mut wrong_purpose.operation {
            target.successor.purpose = AuthorityKeyPurpose::ProductionRelease;
        }
        let wrong_snapshot = snapshot(
            vec![
                provision_root(1, at, "root-1", 1, &keys.root_one),
                authorize_leaf(
                    2,
                    at + Duration::minutes(1),
                    "root-1",
                    1,
                    &keys.root_one,
                    "candidate-1",
                    AuthorityKeyPurpose::CandidatePublisher,
                    &keys.candidate_one,
                ),
                wrong_purpose,
            ],
            rotated_at,
        );
        assert!(matches!(
            replay(&wrong_snapshot, rotated_at),
            Err(BrowserRecipeAuthorityError::InvalidLifecycleTransition
                | BrowserRecipeAuthorityError::InvalidLifecycleAuthority
                | BrowserRecipeAuthorityError::RevisionOrPurposeMismatch)
        ));
    }

    #[test]
    fn revocation_blocks_current_snapshot_even_for_historically_valid_artifact() {
        let keys = SigningFixture::new();
        let at = now();
        let revoked_at = at + Duration::minutes(3);
        let authority = replay(
            &snapshot(
                vec![
                    provision_root(1, at, "root-1", 1, &keys.root_one),
                    authorize_leaf(
                        2,
                        at + Duration::minutes(1),
                        "root-1",
                        1,
                        &keys.root_one,
                        "candidate-1",
                        AuthorityKeyPurpose::CandidatePublisher,
                        &keys.candidate_one,
                    ),
                    rotate_root(
                        3,
                        at + Duration::minutes(2),
                        "root-1",
                        1,
                        &keys.root_one,
                        "root-2",
                        2,
                        &keys.root_two,
                    ),
                    revoke_key(4, revoked_at, "root-2", 1, &keys.root_two, "candidate-1", 1),
                ],
                at + Duration::minutes(4),
            ),
            at + Duration::minutes(4),
        )
        .expect("revoked snapshot replays");
        let rooted = &authority.keys["candidate-1"];
        rooted
            .validate_historical(revoked_at - Duration::seconds(1))
            .expect("historically valid before revocation");
        assert_eq!(
            rooted.validate_historical(revoked_at),
            Err(BrowserRecipeAuthorityError::HistoricalKeyInvalid)
        );
        let legacy = legacy_leaf(
            "candidate-1",
            BrowserRecipeKeyPurpose::CandidatePublisher,
            &keys.candidate_one,
            at + Duration::minutes(1),
        );
        assert_eq!(
            authority.validate_legacy_leaf(&legacy, revoked_at - Duration::seconds(1)),
            Err(BrowserRecipeAuthorityError::ObservedKeyBlocked)
        );

        let active_authority = replay(
            &snapshot(
                vec![
                    provision_root(1, at, "root-1", 1, &keys.root_one),
                    authorize_leaf(
                        2,
                        at + Duration::minutes(1),
                        "root-1",
                        1,
                        &keys.root_one,
                        "candidate-1",
                        AuthorityKeyPurpose::CandidatePublisher,
                        &keys.candidate_one,
                    ),
                ],
                at + Duration::minutes(3),
            ),
            at + Duration::minutes(3),
        )
        .expect("active authority");
        let mut legacy_revoked = legacy;
        legacy_revoked
            .revoke(1, at + Duration::minutes(2))
            .expect("legacy revocation");
        assert_eq!(
            active_authority.validate_legacy_leaf(&legacy_revoked, at + Duration::minutes(1)),
            Err(BrowserRecipeAuthorityError::ObservedKeyBlocked)
        );
    }

    #[test]
    fn compromise_is_emergency_authority_only_and_blocks_from_exact_boundary() {
        let keys = SigningFixture::new();
        let at = now();
        let compromised_from = at + Duration::minutes(2);
        let authority = replay(
            &snapshot(
                vec![
                    provision_root(1, at, "root-1", 1, &keys.root_one),
                    authorize_leaf(
                        2,
                        at + Duration::minutes(1),
                        "root-1",
                        1,
                        &keys.root_one,
                        "candidate-1",
                        AuthorityKeyPurpose::CandidatePublisher,
                        &keys.candidate_one,
                    ),
                    compromise_key(
                        3,
                        at + Duration::minutes(3),
                        "candidate-1",
                        1,
                        compromised_from,
                    ),
                ],
                at + Duration::minutes(3),
            ),
            at + Duration::minutes(3),
        )
        .expect("compromise snapshot");
        let rooted = &authority.keys["candidate-1"];
        rooted
            .validate_historical(compromised_from - Duration::seconds(1))
            .expect("historical signature before compromise boundary");
        assert_eq!(
            rooted.validate_historical(compromised_from),
            Err(BrowserRecipeAuthorityError::HistoricalKeyInvalid)
        );
        assert_eq!(
            rooted.validate_observed_state(authority.snapshot_as_of),
            Err(BrowserRecipeAuthorityError::ObservedKeyBlocked)
        );
    }

    #[test]
    fn snapshot_identity_rejects_rollback_stale_time_and_cross_tenant_replay() {
        let keys = SigningFixture::new();
        let at = now();
        let mutations = vec![
            provision_root(1, at, "root-1", 1, &keys.root_one),
            authorize_leaf(
                2,
                at + Duration::minutes(1),
                "root-1",
                1,
                &keys.root_one,
                "candidate-1",
                AuthorityKeyPurpose::CandidatePublisher,
                &keys.candidate_one,
            ),
        ];
        let current = snapshot(mutations.clone(), at + Duration::minutes(2));
        let current_expectation = current.expectation().expect("current expectation");
        replay(&current, at + Duration::minutes(2)).expect("current snapshot");

        let rolled_back = snapshot(vec![mutations[0].clone()], at + Duration::minutes(2));
        assert!(matches!(
            ReplayedAuthoritySnapshot::replay(
                &rolled_back,
                at + Duration::minutes(2),
                &current_expectation,
            ),
            Err(BrowserRecipeAuthorityError::SnapshotExpectationMismatch)
        ));

        let too_early = snapshot(mutations.clone(), at);
        assert!(matches!(
            replay(&too_early, at + Duration::minutes(2)),
            Err(BrowserRecipeAuthorityError::InvalidMutationSequence)
        ));

        let future = snapshot(mutations.clone(), at + Duration::minutes(3));
        assert!(matches!(
            replay(&future, at + Duration::minutes(2)),
            Err(BrowserRecipeAuthorityError::SnapshotExpectationMismatch)
        ));

        let mut as_of_only = current.clone();
        as_of_only.snapshot_as_of += Duration::seconds(1);
        assert!(matches!(
            ReplayedAuthoritySnapshot::replay(
                &as_of_only,
                at + Duration::minutes(3),
                &current_expectation,
            ),
            Err(BrowserRecipeAuthorityError::SnapshotExpectationMismatch)
        ));

        let mut tenant_swap = current.clone();
        tenant_swap.tenant_id = TenantId::from("tenant-recipe-authority-other");
        let swapped_expectation = tenant_swap.expectation().expect("swapped expectation");
        assert!(matches!(
            ReplayedAuthoritySnapshot::replay(
                &tenant_swap,
                at + Duration::minutes(2),
                &swapped_expectation,
            ),
            Err(BrowserRecipeAuthorityError::InvalidMutationSequence)
        ));

        let mut project_swap = current;
        project_swap.project_id = ProjectId::from("project-recipe-authority-other");
        let swapped_expectation = project_swap.expectation().expect("swapped expectation");
        assert!(matches!(
            ReplayedAuthoritySnapshot::replay(
                &project_swap,
                at + Duration::minutes(2),
                &swapped_expectation,
            ),
            Err(BrowserRecipeAuthorityError::InvalidMutationSequence)
        ));
    }

    #[test]
    fn target_union_revision_and_public_key_uniqueness_fail_closed() {
        let keys = SigningFixture::new();
        let at = now();

        let mut absent_false = provision_root(1, at, "root-1", 1, &keys.root_one);
        if let AuthorityOperation::ProvisionRoot { target, .. } = &mut absent_false.operation {
            target.expected_absent = false;
        }
        absent_false.lifecycle_authority.target = absent_false.operation.target();
        absent_false.lifecycle_authority.operation_digest =
            absent_false.operation_digest().expect("operation digest");
        absent_false.lifecycle_authority.authority_digest = absent_false
            .lifecycle_authority
            .canonical_digest()
            .expect("authority digest");
        assert!(matches!(
            replay(&snapshot(vec![absent_false], at), at),
            Err(BrowserRecipeAuthorityError::InvalidMutationTarget)
        ));

        let stale_revision = snapshot(
            vec![
                provision_root(1, at, "root-1", 1, &keys.root_one),
                authorize_leaf(
                    2,
                    at + Duration::minutes(1),
                    "root-1",
                    2,
                    &keys.root_one,
                    "candidate-1",
                    AuthorityKeyPurpose::CandidatePublisher,
                    &keys.candidate_one,
                ),
            ],
            at + Duration::minutes(1),
        );
        assert!(matches!(
            replay(&stale_revision, at + Duration::minutes(1)),
            Err(BrowserRecipeAuthorityError::RevisionOrPurposeMismatch)
        ));

        let duplicate_root_material = snapshot(
            vec![
                provision_root(1, at, "root-1", 1, &keys.root_one),
                authorize_leaf(
                    2,
                    at + Duration::minutes(1),
                    "root-1",
                    1,
                    &keys.root_one,
                    "candidate-1",
                    AuthorityKeyPurpose::CandidatePublisher,
                    &keys.root_one,
                ),
            ],
            at + Duration::minutes(1),
        );
        assert!(matches!(
            replay(&duplicate_root_material, at + Duration::minutes(1)),
            Err(BrowserRecipeAuthorityError::DuplicateOrInvalidKey)
        ));

        let duplicate_cross_purpose = snapshot(
            vec![
                provision_root(1, at, "root-1", 1, &keys.root_one),
                authorize_leaf(
                    2,
                    at + Duration::minutes(1),
                    "root-1",
                    1,
                    &keys.root_one,
                    "candidate-1",
                    AuthorityKeyPurpose::CandidatePublisher,
                    &keys.candidate_one,
                ),
                authorize_leaf(
                    3,
                    at + Duration::minutes(2),
                    "root-1",
                    1,
                    &keys.root_one,
                    "release-1",
                    AuthorityKeyPurpose::ProductionRelease,
                    &keys.candidate_one,
                ),
            ],
            at + Duration::minutes(2),
        );
        assert!(matches!(
            replay(&duplicate_cross_purpose, at + Duration::minutes(2)),
            Err(BrowserRecipeAuthorityError::DuplicateOrInvalidKey)
        ));
    }

    #[test]
    fn legacy_leaf_exact_match_rejects_purpose_window_and_public_key_substitution() {
        let keys = SigningFixture::new();
        let at = now();
        let authority = replay(
            &snapshot(
                vec![
                    provision_root(1, at, "root-1", 1, &keys.root_one),
                    authorize_leaf(
                        2,
                        at + Duration::minutes(1),
                        "root-1",
                        1,
                        &keys.root_one,
                        "candidate-1",
                        AuthorityKeyPurpose::CandidatePublisher,
                        &keys.candidate_one,
                    ),
                ],
                at + Duration::minutes(2),
            ),
            at + Duration::minutes(2),
        )
        .expect("authority");
        let legacy = legacy_leaf(
            "candidate-1",
            BrowserRecipeKeyPurpose::CandidatePublisher,
            &keys.candidate_one,
            at + Duration::minutes(1),
        );
        authority
            .validate_legacy_leaf(&legacy, at + Duration::minutes(1))
            .expect("exact legacy binding");

        let mut wrong_purpose = legacy.clone();
        wrong_purpose.purpose = BrowserRecipeKeyPurpose::ProductionRelease;
        let mut wrong_window = legacy.clone();
        wrong_window.valid_until += Duration::seconds(1);
        let mut wrong_public_key = legacy;
        wrong_public_key.public_key_hex = public_key_hex(&keys.candidate_two);
        for substituted in [wrong_purpose, wrong_window, wrong_public_key] {
            assert_eq!(
                authority.validate_legacy_leaf(&substituted, at + Duration::minutes(1)),
                Err(BrowserRecipeAuthorityError::LegacyTrustMismatch)
            );
        }
    }

    #[test]
    fn delegation_swap_root_swap_and_lineage_truncation_are_rejected() {
        let keys = SigningFixture::new();
        let at = now();
        let make_authority = || {
            replay(
                &snapshot(
                    vec![
                        provision_root(1, at, "root-1", 1, &keys.root_one),
                        authorize_leaf(
                            2,
                            at + Duration::minutes(1),
                            "root-1",
                            1,
                            &keys.root_one,
                            "candidate-1",
                            AuthorityKeyPurpose::CandidatePublisher,
                            &keys.candidate_one,
                        ),
                        rotate_root(
                            3,
                            at + Duration::minutes(2),
                            "root-1",
                            1,
                            &keys.root_one,
                            "root-2",
                            2,
                            &keys.root_two,
                        ),
                    ],
                    at + Duration::minutes(3),
                ),
                at + Duration::minutes(3),
            )
            .expect("authority")
        };
        let legacy = legacy_leaf(
            "candidate-1",
            BrowserRecipeKeyPurpose::CandidatePublisher,
            &keys.candidate_one,
            at + Duration::minutes(1),
        );

        let mut delegation_swap = make_authority();
        delegation_swap
            .keys
            .get_mut("candidate-1")
            .expect("candidate")
            .delegation
            .as_mut()
            .expect("delegation")
            .authorization_digest = "f".repeat(64);
        assert_eq!(
            delegation_swap.validate_legacy_leaf(&legacy, at + Duration::minutes(1)),
            Err(BrowserRecipeAuthorityError::DelegationMismatch)
        );

        let mut root_swap = make_authority();
        root_swap
            .keys
            .get_mut("candidate-1")
            .expect("candidate")
            .delegation
            .as_mut()
            .expect("delegation")
            .authorizing_root_key_id = "root-2".into();
        assert_eq!(
            root_swap.validate_legacy_leaf(&legacy, at + Duration::minutes(1)),
            Err(BrowserRecipeAuthorityError::DelegationMismatch)
        );

        let mut lineage_truncation = make_authority();
        lineage_truncation
            .keys
            .get_mut("candidate-1")
            .expect("candidate")
            .lineage_digest = "0".repeat(64);
        assert_eq!(
            lineage_truncation.validate_legacy_leaf(&legacy, at + Duration::minutes(1)),
            Err(BrowserRecipeAuthorityError::DelegationMismatch)
        );
    }

    #[test]
    fn lifecycle_and_key_windows_use_half_open_boundaries() {
        let keys = SigningFixture::new();
        let at = now();
        let mut authority_expired = provision_root(1, at, "root-1", 1, &keys.root_one);
        authority_expired.lifecycle_authority.valid_until = at;
        authority_expired.lifecycle_authority.authority_digest = authority_expired
            .lifecycle_authority
            .canonical_digest()
            .expect("authority digest");
        assert!(matches!(
            replay(&snapshot(vec![authority_expired], at), at),
            Err(BrowserRecipeAuthorityError::InvalidLifecycleAuthority)
        ));

        let mut key_expired = provision_root(1, at, "root-1", 1, &keys.root_one);
        if let AuthorityOperation::ProvisionRoot {
            valid_from,
            valid_until,
            ..
        } = &mut key_expired.operation
        {
            *valid_from = at - Duration::minutes(1);
            *valid_until = at;
        }
        key_expired.lifecycle_authority.target = key_expired.operation.target();
        key_expired.lifecycle_authority.operation_digest =
            key_expired.operation_digest().expect("operation digest");
        key_expired.lifecycle_authority.authority_digest = key_expired
            .lifecycle_authority
            .canonical_digest()
            .expect("authority digest");
        assert!(matches!(
            replay(&snapshot(vec![key_expired], at), at),
            Err(BrowserRecipeAuthorityError::DuplicateOrInvalidKey
                | BrowserRecipeAuthorityError::InvalidSignature)
        ));
    }
}
