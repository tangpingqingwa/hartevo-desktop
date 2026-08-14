//! Service, registration, read proposal, and evidence-only adoption seam.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, ModelError, ProjectionState, Revision, ShopifyApiVersion, ShopifyOrderResultScope,
};
use crate::provider::{
    GraphqlResponse, PageInfo, ProviderProvenance, ShopifyAdminProvider, ShopifyOrderEvidence,
    ShopifyProviderError,
};
use crate::{
    SHOPIFY_ADMIN_API_VERSION, SHOPIFY_ADMIN_PROVIDER_ID, SHOPIFY_ORDER_RESULT_CONTRACT_VERSION,
    SHOPIFY_ORDER_RESULT_PLUGIN_VERSION, SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT,
    SHOPIFY_ORDER_RESULT_SCHEMA_VERSION, SHOPIFY_ORDER_RESULT_SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShopifyServiceError {
    #[error("invalid Shopify order-result model: {0}")]
    Model(#[from] ModelError),
    #[error("contract validation failed: {0}")]
    Contract(String),
    #[error("provider error: {0}")]
    Provider(#[from] ShopifyProviderError),
    #[error("service registration is revoked")]
    RegistrationRevoked,
    #[error("service registration is stale or tampered")]
    RegistrationTampered,
    #[error("read proposal is stale or tampered")]
    ProposalTampered,
    #[error("evidence is stale or tampered")]
    EvidenceTampered,
    #[error("scope revision fence mismatch")]
    ScopeFenceMismatch,
    #[error("permission lease is expired")]
    PermissionExpired,
    #[error("requested page is outside the Layer-1 bound")]
    PaginationBoundExceeded,
    #[error("adoption is evidence-only in Layer 1")]
    AdoptionIsEvidenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyRegistration {
    pub schema_version: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub provider_implementation_digest: Digest,
    pub api_version: String,
    pub shop_domain: String,
    pub order_id: String,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub permission_lease_revision: Revision,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub project_id: String,
    pub project_revision: Revision,
    pub mission_id: String,
    pub mission_revision: Revision,
    pub work_product_id: String,
    pub work_product_revision: Revision,
    pub policy_revision: String,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

impl ShopifyRegistration {
    fn new(
        scope: &ShopifyOrderResultScope,
        provider: &ShopifyAdminProvider,
    ) -> Result<Self, ShopifyServiceError> {
        let registration_revision = Revision::new(1)?;
        let contract_digest = contract_digest();
        let provider_digest = provider.provider_digest().clone();
        let provider_implementation_digest = provider.implementation_digest().clone();
        let fields = registration_fields(
            scope,
            &contract_digest,
            &provider_digest,
            &provider_implementation_digest,
            registration_revision,
        );
        let registration_digest = Digest::from_fields("hartevo:shopify-registration/v1", &fields);
        Ok(Self {
            schema_version: SHOPIFY_ORDER_RESULT_SCHEMA_VERSION.to_owned(),
            plugin_version: SHOPIFY_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: SHOPIFY_ORDER_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: SHOPIFY_ADMIN_PROVIDER_ID.to_owned(),
            provider_digest,
            provider_implementation_digest,
            api_version: scope.api_version().as_str().to_owned(),
            shop_domain: scope.shop().as_str().to_owned(),
            order_id: scope.order_id().as_str().to_owned(),
            secret_reference_digest: scope.secret_reference().reference_digest().clone(),
            credential_revision: scope.secret_reference().credential_revision(),
            permission_lease_revision: scope.permission_lease().revision(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest().clone(),
            project_id: scope.project().id().as_str().to_owned(),
            project_revision: scope.project().revision(),
            mission_id: scope.mission().id().as_str().to_owned(),
            mission_revision: scope.mission().revision(),
            work_product_id: scope.work_product().id().as_str().to_owned(),
            work_product_revision: scope.work_product().revision(),
            policy_revision: scope.policy_revision().as_str().to_owned(),
            registration_revision,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn verify(&self, scope: &ShopifyOrderResultScope, provider: &ShopifyAdminProvider) -> bool {
        if self.state != RegistrationState::Active
            || self.scope_digest != *scope.scope_digest()
            || self.provider_digest != *provider.provider_digest()
            || self.provider_implementation_digest != *provider.implementation_digest()
            || self.permission_digest != scope.permission_digest()
            || self.api_version != scope.api_version().as_str()
            || self.shop_domain != scope.shop().as_str()
            || self.order_id != scope.order_id().as_str()
        {
            return false;
        }
        let expected = Digest::from_fields(
            "hartevo:shopify-registration/v1",
            &registration_fields(
                scope,
                &self.contract_digest,
                &self.provider_digest,
                &self.provider_implementation_digest,
                self.registration_revision,
            ),
        );
        expected == self.registration_digest
    }

    pub fn revoke(&mut self) -> Result<(), ShopifyServiceError> {
        if self.state == RegistrationState::Revoked {
            return Err(ShopifyServiceError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }
}

fn registration_fields(
    scope: &ShopifyOrderResultScope,
    contract_digest: &Digest,
    provider_digest: &Digest,
    provider_implementation_digest: &Digest,
    registration_revision: Revision,
) -> Vec<String> {
    vec![
        SHOPIFY_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
        SHOPIFY_ORDER_RESULT_CONTRACT_VERSION.to_owned(),
        contract_digest.as_str().to_owned(),
        SHOPIFY_ADMIN_PROVIDER_ID.to_owned(),
        provider_digest.as_str().to_owned(),
        provider_implementation_digest.as_str().to_owned(),
        scope.api_version().as_str().to_owned(),
        scope.shop().as_str().to_owned(),
        scope.order_id().as_str().to_owned(),
        scope
            .secret_reference()
            .reference_digest()
            .as_str()
            .to_owned(),
        scope
            .secret_reference()
            .credential_revision()
            .get()
            .to_string(),
        scope.permission_lease().revision().get().to_string(),
        scope.permission_digest().as_str().to_owned(),
        scope.scope_digest().as_str().to_owned(),
        scope.project().id().as_str().to_owned(),
        scope.project().revision().get().to_string(),
        scope.mission().id().as_str().to_owned(),
        scope.mission().revision().get().to_string(),
        scope.work_product().id().as_str().to_owned(),
        scope.work_product().revision().get().to_string(),
        scope.policy_revision().as_str().to_owned(),
        registration_revision.get().to_string(),
    ]
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyOrderReadProposal {
    pub api_version: ShopifyApiVersion,
    pub shop_domain: String,
    pub order_id: String,
    pub page_number: u16,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor_digest: Option<Digest>,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub proposal_digest: Digest,
}

impl ShopifyOrderReadProposal {
    fn new(
        scope: &ShopifyOrderResultScope,
        registration: &ShopifyRegistration,
        page_number: u16,
        page_size: u16,
        cursor_digest: Option<Digest>,
    ) -> Result<Self, ShopifyServiceError> {
        if page_number == 0
            || page_number > crate::model::MAX_PAGES
            || page_size == 0
            || page_size > crate::model::PAGE_SIZE
        {
            return Err(ShopifyServiceError::PaginationBoundExceeded);
        }
        let query_digest = Digest::sha256(SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT.as_bytes());
        let mut proposal = Self {
            api_version: scope.api_version().clone(),
            shop_domain: scope.shop().as_str().to_owned(),
            order_id: scope.order_id().as_str().to_owned(),
            page_number,
            page_size,
            max_pages: crate::model::MAX_PAGES,
            cursor_digest,
            query_digest,
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            proposal_digest: Digest::from_text("uncomputed"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalFingerprint {
            api_version: &self.api_version,
            shop_domain: &self.shop_domain,
            order_id: &self.order_id,
            page_number: self.page_number,
            page_size: self.page_size,
            max_pages: self.max_pages,
            cursor_digest: &self.cursor_digest,
            query_digest: &self.query_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
        })
    }

    pub fn verify_digest(&self) -> bool {
        self.proposal_digest == self.compute_digest()
    }

    pub fn api_version(&self) -> &ShopifyApiVersion {
        &self.api_version
    }

    pub fn shop_domain(&self) -> &str {
        &self.shop_domain
    }

    pub fn order_id(&self) -> &str {
        &self.order_id
    }

    pub fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor_digest.as_ref()
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn next_page(&self, page_info: &PageInfo) -> Result<Option<Self>, ShopifyServiceError> {
        if !page_info.has_next_page {
            return Ok(None);
        }
        if self.page_number >= self.max_pages {
            return Err(ShopifyServiceError::PaginationBoundExceeded);
        }
        let Some(cursor_digest) = page_info.end_cursor_digest.clone() else {
            return Err(ShopifyServiceError::ProposalTampered);
        };
        let mut next = self.clone();
        next.page_number = next.page_number.saturating_add(1);
        next.cursor_digest = Some(cursor_digest);
        next.proposal_digest = next.compute_digest();
        Ok(Some(next))
    }
}

#[derive(Clone, Debug, Serialize)]
struct ProposalFingerprint<'a> {
    api_version: &'a ShopifyApiVersion,
    shop_domain: &'a str,
    order_id: &'a str,
    page_number: u16,
    page_size: u16,
    max_pages: u16,
    cursor_digest: &'a Option<Digest>,
    query_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    registration_digest: &'a Digest,
    registration_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionMode {
    EvidenceOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyAdoptionProposal {
    pub mode: AdoptionMode,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub work_product_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub source_evidence_digest: Digest,
    pub source_order_revision_digest: Option<Digest>,
    pub projection_state: ProjectionState,
    pub evidence: ShopifyOrderEvidence,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_work_product: bool,
    pub proposal_digest: Digest,
}

impl ShopifyAdoptionProposal {
    fn new(
        scope: &ShopifyOrderResultScope,
        registration: &ShopifyRegistration,
        evidence: &ShopifyOrderEvidence,
    ) -> Self {
        let source_order_revision_digest = evidence
            .projection
            .as_ref()
            .map(|projection| projection.order_revision_digest.clone());
        let mut proposal = Self {
            mode: AdoptionMode::EvidenceOnly,
            mission_id: scope.mission().id().as_str().to_owned(),
            project_id: scope.project().id().as_str().to_owned(),
            work_product_id: scope.work_product().id().as_str().to_owned(),
            work_product_revision: scope.work_product().revision(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest(),
            registration_digest: registration.registration_digest.clone(),
            source_evidence_digest: evidence.evidence_digest.clone(),
            source_order_revision_digest,
            projection_state: evidence.projection_state,
            evidence: evidence.clone(),
            connected: false,
            native: false,
            first_party: false,
            adopts_work_product: false,
            proposal_digest: Digest::from_text("uncomputed"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&AdoptionFingerprint {
            mode: self.mode,
            mission_id: &self.mission_id,
            project_id: &self.project_id,
            work_product_id: &self.work_product_id,
            work_product_revision: self.work_product_revision,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            source_evidence_digest: &self.source_evidence_digest,
            source_order_revision_digest: &self.source_order_revision_digest,
            projection_state: self.projection_state,
        })
    }

    pub fn verify_digest(&self) -> bool {
        self.proposal_digest == self.compute_digest()
    }

    pub fn is_evidence_only(&self) -> bool {
        matches!(self.mode, AdoptionMode::EvidenceOnly)
            && !self.connected
            && !self.native
            && !self.first_party
            && !self.adopts_work_product
    }
}

#[derive(Clone, Debug, Serialize)]
struct AdoptionFingerprint<'a> {
    mode: AdoptionMode,
    mission_id: &'a str,
    project_id: &'a str,
    work_product_id: &'a str,
    work_product_revision: Revision,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    registration_digest: &'a Digest,
    source_evidence_digest: &'a Digest,
    source_order_revision_digest: &'a Option<Digest>,
    projection_state: ProjectionState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_version: String,
    pub operations: Vec<String>,
    pub mutating_operations: Vec<String>,
    pub accepted_provenance: Vec<ProviderProvenance>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub payment_authority: bool,
}

#[derive(Clone, Debug)]
pub struct ShopifyOrderResultService {
    scope: ShopifyOrderResultScope,
    provider: ShopifyAdminProvider,
    registration: ShopifyRegistration,
    active: bool,
}

impl ShopifyOrderResultService {
    pub fn new(
        scope: ShopifyOrderResultScope,
        provider: ShopifyAdminProvider,
    ) -> Result<Self, ShopifyServiceError> {
        crate::ShopifyOrderResultContract::baseline()?;
        if scope.api_version().as_str() != SHOPIFY_ADMIN_API_VERSION
            || provider.definition().api_version != SHOPIFY_ADMIN_API_VERSION
        {
            return Err(ShopifyServiceError::ScopeFenceMismatch);
        }
        let registration = ShopifyRegistration::new(&scope, &provider)?;
        Ok(Self {
            scope,
            provider,
            registration,
            active: true,
        })
    }

    pub fn scope(&self) -> &ShopifyOrderResultScope {
        &self.scope
    }

    pub fn provider(&self) -> &ShopifyAdminProvider {
        &self.provider
    }

    pub fn registration(&self) -> &ShopifyRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.active && self.registration.is_active()
    }

    pub fn describe_capabilities(&self) -> ShopifyCapabilities {
        ShopifyCapabilities {
            service_id: SHOPIFY_ORDER_RESULT_SERVICE_ID.to_owned(),
            provider_id: SHOPIFY_ADMIN_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_SHOPIFY_ORDER_RESULT_CONSUMER_ID.to_owned(),
            api_version: SHOPIFY_ADMIN_API_VERSION.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "compile_read_proposal".to_owned(),
                "record_read_evidence".to_owned(),
                "propose_adoption".to_owned(),
                "consume_result".to_owned(),
            ],
            mutating_operations: Vec::new(),
            accepted_provenance: vec![
                ProviderProvenance::Fixture,
                ProviderProvenance::Recording,
                ProviderProvenance::Loopback,
                ProviderProvenance::BlockedEnv,
            ],
            connected: false,
            native: false,
            first_party: false,
            payment_authority: false,
        }
    }

    pub fn compile_read_proposal(&self) -> Result<ShopifyOrderReadProposal, ShopifyServiceError> {
        self.compile_read_proposal_with_page(1, crate::model::PAGE_SIZE, None)
    }

    pub fn compile_order_read_proposal(
        &self,
    ) -> Result<ShopifyOrderReadProposal, ShopifyServiceError> {
        self.compile_read_proposal()
    }

    pub fn compile_read_proposal_with_page(
        &self,
        page_number: u16,
        page_size: u16,
        cursor_digest: Option<Digest>,
    ) -> Result<ShopifyOrderReadProposal, ShopifyServiceError> {
        self.ensure_active()?;
        ShopifyOrderReadProposal::new(
            &self.scope,
            &self.registration,
            page_number,
            page_size,
            cursor_digest,
        )
    }

    pub fn compile_read_proposal_at(
        &self,
        now_epoch_seconds: u64,
    ) -> Result<ShopifyOrderReadProposal, ShopifyServiceError> {
        self.ensure_active()?;
        if self.scope.permission_lease().is_expired(now_epoch_seconds) {
            return Err(ShopifyServiceError::PermissionExpired);
        }
        self.compile_read_proposal()
    }

    pub fn record_read_evidence(
        &self,
        proposal: &ShopifyOrderReadProposal,
        response: GraphqlResponse<'_>,
    ) -> Result<ShopifyOrderEvidence, ShopifyServiceError> {
        self.ensure_active()?;
        self.verify_proposal(proposal)?;
        Ok(self.provider.record_order_response(proposal, response)?)
    }

    pub fn record_read_evidence_at(
        &self,
        proposal: &ShopifyOrderReadProposal,
        response: GraphqlResponse<'_>,
        now_epoch_seconds: u64,
    ) -> Result<ShopifyOrderEvidence, ShopifyServiceError> {
        self.ensure_active()?;
        self.verify_proposal(proposal)?;
        if self.scope.permission_lease().is_expired(now_epoch_seconds) {
            return Ok(self
                .provider
                .record_blocked_env(proposal, crate::BlockedEnvReason::PermissionExpired)?);
        }
        Ok(self.provider.record_order_response(proposal, response)?)
    }

    pub fn record_blocked_env(
        &self,
        proposal: &ShopifyOrderReadProposal,
        reason: crate::BlockedEnvReason,
    ) -> Result<ShopifyOrderEvidence, ShopifyServiceError> {
        self.ensure_active()?;
        self.verify_proposal(proposal)?;
        Ok(self.provider.record_blocked_env(proposal, reason)?)
    }

    pub fn next_page_proposal(
        &self,
        proposal: &ShopifyOrderReadProposal,
        page_info: &PageInfo,
    ) -> Result<Option<ShopifyOrderReadProposal>, ShopifyServiceError> {
        self.ensure_active()?;
        self.verify_proposal(proposal)?;
        proposal.next_page(page_info)
    }

    pub fn propose_adoption(
        &self,
        evidence: &ShopifyOrderEvidence,
    ) -> Result<ShopifyAdoptionProposal, ShopifyServiceError> {
        self.ensure_active()?;
        if !self.registration.verify(&self.scope, &self.provider) {
            return Err(ShopifyServiceError::RegistrationTampered);
        }
        if !evidence.verify_digest()
            || evidence.scope_digest != *self.scope.scope_digest()
            || evidence.permission_digest != self.scope.permission_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provider_digest != *self.provider.provider_digest()
        {
            return Err(ShopifyServiceError::EvidenceTampered);
        }
        Ok(ShopifyAdoptionProposal::new(
            &self.scope,
            &self.registration,
            evidence,
        ))
    }

    pub fn revoke_registration(&mut self) -> Result<(), ShopifyServiceError> {
        self.registration.revoke()?;
        self.active = false;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), ShopifyServiceError> {
        if !self.is_active() {
            return Err(ShopifyServiceError::RegistrationRevoked);
        }
        if !self.registration.verify(&self.scope, &self.provider) {
            return Err(ShopifyServiceError::RegistrationTampered);
        }
        Ok(())
    }

    fn verify_proposal(
        &self,
        proposal: &ShopifyOrderReadProposal,
    ) -> Result<(), ShopifyServiceError> {
        if !proposal.verify_digest() {
            return Err(ShopifyServiceError::ProposalTampered);
        }
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.permission_digest != self.scope.permission_digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.api_version.as_str() != self.scope.api_version().as_str()
            || proposal.shop_domain != self.scope.shop().as_str()
            || proposal.order_id != self.scope.order_id().as_str()
        {
            return Err(ShopifyServiceError::ScopeFenceMismatch);
        }
        Ok(())
    }
}
