use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{Mission, MissionId, WorkProduct, WorkProductId, WorkProductStatus};
use serde::Serialize;

use crate::model::{
    GithubProposalTarget, GithubWorkProposal, GithubWorkReadProjection, GithubWorkReadRequest,
};
use crate::provider::{GithubAppCredentialResolver, GithubAppWorkProvider};
use crate::transport::GithubWorkHttpTransport;
use crate::{
    DEV_WORK_SERVICE_ID, GITHUB_WORK_CAPABILITY_ID, GITHUB_WORK_PROPOSAL_CAPABILITY_ID,
    GithubWorkError, digest_json, github_work_plugin_digest, validate_text,
};

/// Typed Layer 1 service identity.  It has no Store, keyring, Browser Profile,
/// or Effect handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DevWorkService;

impl DevWorkService {
    pub const ID: &'static str = DEV_WORK_SERVICE_ID;

    pub const fn new() -> Self {
        Self
    }

    pub const fn schema() -> &'static str {
        crate::GITHUB_WORK_SERVICE_SCHEMA
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkProposalInput {
    pub read: GithubWorkReadRequest,
    pub target: GithubProposalTarget,
    pub title: Option<String>,
    pub body: String,
    pub work_product_id: WorkProductId,
}

impl GithubWorkProposalInput {
    pub fn new(
        read: GithubWorkReadRequest,
        target: GithubProposalTarget,
        title: Option<String>,
        body: impl Into<String>,
        work_product_id: WorkProductId,
    ) -> Result<Self, GithubWorkError> {
        let input = Self {
            read,
            target,
            title,
            body: body.into(),
            work_product_id,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        self.read.validate()?;
        self.target.validate()?;
        if let Some(title) = &self.title {
            validate_text(title, "proposal title", 512)?;
        }
        validate_text(&self.body, "proposal body", 64 * 1024)?;
        if self.work_product_id.as_str().trim().is_empty() {
            return Err(GithubWorkError::InvalidInput(
                "proposal Work Product id must be present".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGithubWorkReadResult {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub projection: GithubWorkReadProjection,
    pub model_visible: bool,
    pub adopted: bool,
    pub native_connected: bool,
    pub result_digest: String,
}

impl MissionGithubWorkReadResult {
    fn new(
        mission: &Mission,
        projection: GithubWorkReadProjection,
    ) -> Result<Self, GithubWorkError> {
        projection.validate()?;
        let mut result = Self {
            tenant_id: mission.tenant_id.as_str().to_owned(),
            project_id: mission.project_id.as_str().to_owned(),
            mission_id: mission.id.as_str().to_owned(),
            native_connected: projection.metadata.is_connected(),
            projection,
            model_visible: true,
            adopted: true,
            result_digest: String::new(),
        };
        result.result_digest = digest_json(&(
            &result.tenant_id,
            &result.project_id,
            &result.mission_id,
            &result.projection,
            result.model_visible,
            result.adopted,
            result.native_connected,
        ))?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        self.projection.validate()?;
        if !self.model_visible
            || !self.adopted
            || self.native_connected != self.projection.metadata.is_connected()
        {
            return Err(GithubWorkError::InvalidInput(
                "Mission GitHub read result is not an adopted projection".to_owned(),
            ));
        }
        let expected = digest_json(&(
            &self.tenant_id,
            &self.project_id,
            &self.mission_id,
            &self.projection,
            self.model_visible,
            self.adopted,
            self.native_connected,
        ))?;
        if expected != self.result_digest {
            return Err(GithubWorkError::InvalidInput(
                "Mission GitHub read result digest does not match".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGithubWorkProposalResult {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub proposal: GithubWorkProposal,
    pub model_visible: bool,
    pub adopted: bool,
    pub result_digest: String,
}

impl MissionGithubWorkProposalResult {
    fn new(mission: &Mission, proposal: GithubWorkProposal) -> Result<Self, GithubWorkError> {
        proposal.validate()?;
        let mut result = Self {
            tenant_id: mission.tenant_id.as_str().to_owned(),
            project_id: mission.project_id.as_str().to_owned(),
            mission_id: mission.id.as_str().to_owned(),
            proposal,
            model_visible: true,
            adopted: true,
            result_digest: String::new(),
        };
        result.result_digest = digest_json(&(
            &result.tenant_id,
            &result.project_id,
            &result.mission_id,
            &result.proposal,
            result.model_visible,
            result.adopted,
        ))?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        self.proposal.validate()?;
        if !self.model_visible || !self.adopted {
            return Err(GithubWorkError::InvalidInput(
                "Mission GitHub proposal result is not an adopted preview".to_owned(),
            ));
        }
        let expected = digest_json(&(
            &self.tenant_id,
            &self.project_id,
            &self.mission_id,
            &self.proposal,
            self.model_visible,
            self.adopted,
        ))?;
        if expected != self.result_digest {
            return Err(GithubWorkError::InvalidInput(
                "Mission GitHub proposal result digest does not match".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MissionGithubWorkConsumer;

impl MissionGithubWorkConsumer {
    pub const fn new() -> Self {
        Self
    }

    pub fn consume_read(
        &self,
        mission: &Mission,
        projection: GithubWorkReadProjection,
    ) -> Result<MissionGithubWorkReadResult, GithubWorkError> {
        ensure_mission_capability(mission, GITHUB_WORK_CAPABILITY_ID)?;
        if projection.metadata.plugin_digest != github_work_plugin_digest() {
            return Err(GithubWorkError::ScopeMismatch(
                "GitHub read projection belongs to another plugin digest".to_owned(),
            ));
        }
        MissionGithubWorkReadResult::new(mission, projection)
    }

    pub fn consume_proposal(
        &self,
        mission: &Mission,
        proposal: GithubWorkProposal,
    ) -> Result<MissionGithubWorkProposalResult, GithubWorkError> {
        ensure_mission_capability(mission, GITHUB_WORK_CAPABILITY_ID)?;
        ensure_mission_capability(mission, GITHUB_WORK_PROPOSAL_CAPABILITY_ID)?;
        if proposal.tenant_id != mission.tenant_id
            || proposal.project_id != mission.project_id
            || proposal.mission_id != mission.id
            || proposal.metadata.plugin_digest != github_work_plugin_digest()
        {
            return Err(GithubWorkError::ScopeMismatch(
                "GitHub proposal is bound to another Mission scope".to_owned(),
            ));
        }
        MissionGithubWorkProposalResult::new(mission, proposal)
    }
}

pub struct GithubWorkService<T, R>
where
    T: GithubWorkHttpTransport,
    R: GithubAppCredentialResolver,
{
    provider: GithubAppWorkProvider<T, R>,
    consumer: MissionGithubWorkConsumer,
}

impl<T, R> fmt::Debug for GithubWorkService<T, R>
where
    T: GithubWorkHttpTransport,
    R: GithubAppCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkService")
            .field("provider", &self.provider)
            .field("consumer", &self.consumer)
            .finish()
    }
}

impl<T, R> GithubWorkService<T, R>
where
    T: GithubWorkHttpTransport,
    R: GithubAppCredentialResolver,
{
    pub fn new(provider: GithubAppWorkProvider<T, R>) -> Self {
        Self {
            provider,
            consumer: MissionGithubWorkConsumer::new(),
        }
    }

    pub fn provider(&self) -> &GithubAppWorkProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GithubAppWorkProvider<T, R> {
        &mut self.provider
    }

    pub fn read(
        &mut self,
        mission: &Mission,
        request: &GithubWorkReadRequest,
        now: DateTime<Utc>,
    ) -> Result<MissionGithubWorkReadResult, GithubWorkError> {
        self.validate_scope(mission)?;
        ensure_mission_capability(mission, GITHUB_WORK_CAPABILITY_ID)?;
        let projection = self.provider.read(request, now)?;
        self.consumer.consume_read(mission, projection)
    }

    pub fn propose(
        &mut self,
        mission: &Mission,
        input: GithubWorkProposalInput,
        now: DateTime<Utc>,
    ) -> Result<MissionGithubWorkProposalResult, GithubWorkError> {
        input.validate()?;
        self.validate_scope(mission)?;
        ensure_mission_capability(mission, GITHUB_WORK_CAPABILITY_ID)?;
        ensure_mission_capability(mission, GITHUB_WORK_PROPOSAL_CAPABILITY_ID)?;
        let work_product = mission
            .work_products
            .iter()
            .find(|work_product| work_product.id == input.work_product_id)
            .ok_or(GithubWorkError::ItemNotFound)?;
        validate_proposal_work_product(work_product)?;
        let projection = self.provider.read(&input.read, now)?;
        let proposal = GithubWorkProposal::seal(
            input.target,
            input.title,
            input.body,
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            work_product.id.clone(),
            work_product.revision,
            work_product.content_digest.clone(),
            &projection,
        )?;
        self.consumer.consume_proposal(mission, proposal)
    }

    fn validate_scope(&self, mission: &Mission) -> Result<(), GithubWorkError> {
        let connection = self.provider.connection();
        if connection.mission_id() != &mission.id
            || connection.scope().tenant_id() != mission.tenant_id.as_str()
            || connection.scope().project_id() != mission.project_id.as_str()
        {
            return Err(GithubWorkError::ScopeMismatch(
                "GitHub provider is mounted outside the Mission tenant/project scope".to_owned(),
            ));
        }
        Ok(())
    }
}

fn ensure_mission_capability(mission: &Mission, capability: &str) -> Result<(), GithubWorkError> {
    if !mission.contract.enabled_capabilities.contains(capability)
        || mission.contract.forbidden_capabilities.contains(capability)
    {
        return Err(GithubWorkError::ScopeMismatch(format!(
            "Mission does not authorize capability {capability}"
        )));
    }
    Ok(())
}

fn validate_proposal_work_product(work_product: &WorkProduct) -> Result<(), GithubWorkError> {
    work_product
        .validate()
        .map_err(|error| GithubWorkError::InvalidInput(error.to_string()))?;
    if !matches!(
        work_product.status,
        WorkProductStatus::ReadyForReview | WorkProductStatus::Accepted
    ) {
        return Err(GithubWorkError::InvalidInput(
            "GitHub proposal requires an adoptable Work Product".to_owned(),
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn _mission_id_for_result(mission: &Mission) -> &MissionId {
    &mission.id
}
