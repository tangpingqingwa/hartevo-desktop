//! Typed, metadata-only Amazon Personalize provider seams.
//!
//! There is deliberately no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client, request body, user-profile field, catalog field, or model-byte path
//! in this Layer-1 crate. Implementations are bounded transports for fixtures,
//! recordings, loopback tests, and the explicit `BLOCKED_ENV` gap.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{AwsPersonalizeRecommendationError, AwsPersonalizeTransportError, Result};
use crate::model::{
    AwsPersonalizeRecommendationScope, CampaignMetadata, CampaignMetadataInput, CampaignStatus,
    Digest, FilterIdentity, ItemFingerprint, ModelRevision, RecommendationItem,
    RecommendationItemKind, RecommendationOperation, RecommendationResult, RecommenderMetadata,
    RecommenderMetadataInput, RecommenderStatus, ServingTarget, SolutionVersionIdentity,
    TransportProvenance, UserFingerprint,
};
use crate::{
    MAX_RESPONSE_BYTES, MAX_RESULTS, PERSONALIZE_API_VERSION, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID,
};

pub const DESCRIBE_CAMPAIGN_TARGET: &str = "AmazonPersonalize.DescribeCampaign";
pub const DESCRIBE_RECOMMENDER_TARGET: &str = "AmazonPersonalize.DescribeRecommender";
pub const GET_RECOMMENDATIONS_TARGET: &str = "AmazonPersonalize.GetRecommendations";
pub const GET_PERSONALIZED_RANKING_TARGET: &str = "AmazonPersonalize.GetPersonalizedRanking";
pub const PERSONALIZE_OPERATION_PATH: &str = "/";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsPersonalizeOperation {
    DescribeCampaign,
    DescribeRecommender,
    GetRecommendations,
    GetPersonalizedRanking,
}

impl AwsPersonalizeOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeCampaign => "DescribeCampaign",
            Self::DescribeRecommender => "DescribeRecommender",
            Self::GetRecommendations => "GetRecommendations",
            Self::GetPersonalizedRanking => "GetPersonalizedRanking",
        }
    }

    pub const fn target(self) -> &'static str {
        match self {
            Self::DescribeCampaign => DESCRIBE_CAMPAIGN_TARGET,
            Self::DescribeRecommender => DESCRIBE_RECOMMENDER_TARGET,
            Self::GetRecommendations => GET_RECOMMENDATIONS_TARGET,
            Self::GetPersonalizedRanking => GET_PERSONALIZED_RANKING_TARGET,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsPersonalizeProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: u64,
    pub release: String,
    pub api_revision: String,
    pub api_version: String,
    pub operations: Vec<AwsPersonalizeOperation>,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

impl Default for AwsPersonalizeProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsPersonalizeProviderDefinition {
    pub fn new() -> Self {
        let operations = vec![
            AwsPersonalizeOperation::DescribeCampaign,
            AwsPersonalizeOperation::DescribeRecommender,
            AwsPersonalizeOperation::GetRecommendations,
            AwsPersonalizeOperation::GetPersonalizedRanking,
        ];
        let provider_digest = Digest::from_parts(
            "aws-personalize-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_version", PLUGIN_VERSION.to_owned()),
                ("provider_revision", "1".to_owned()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION.to_owned(),
            provider_revision: 1,
            release: "recording-r1".to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            api_version: PERSONALIZE_API_VERSION.to_owned(),
            operations,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new();
        if self.provider_id != expected.provider_id
            || self.provider_version != expected.provider_version
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.api_revision != expected.api_revision
            || self.api_version != expected.api_version
            || self.operations != expected.operations
            || self.provider_digest != expected.provider_digest
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
        {
            return Err(AwsPersonalizeRecommendationError::ProviderDrift);
        }
        Ok(())
    }
}

pub trait AwsPersonalizeTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_campaign(
        &mut self,
        request: &DescribeCampaignRequest,
    ) -> std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError>;

    fn describe_recommender(
        &mut self,
        request: &DescribeRecommenderRequest,
    ) -> std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError>;

    fn get_recommendations(
        &mut self,
        request: &GetRecommendationsRequest,
    ) -> std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError>;

    fn get_personalized_ranking(
        &mut self,
        request: &GetPersonalizedRankingRequest,
    ) -> std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsPersonalizeOperation,
    pub scope_digest: Digest,
    pub target_digest: Option<Digest>,
    pub filter_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeCampaignRequest {
    scope_digest: Digest,
    campaign_digest: Digest,
    request_digest: Digest,
    path_digest: Digest,
}

impl DescribeCampaignRequest {
    pub fn for_scope(scope: &AwsPersonalizeRecommendationScope) -> Result<Self> {
        let campaign = scope
            .campaign()
            .ok_or(AwsPersonalizeRecommendationError::UnsupportedOperation)?;
        let request_digest = Digest::from_parts(
            "aws-personalize-describe-campaign-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("campaign", campaign.digest().as_str().to_owned()),
            ],
        );
        let path_digest = Digest::from_text(format!(
            "POST {PERSONALIZE_OPERATION_PATH} {DESCRIBE_CAMPAIGN_TARGET} campaign={}",
            campaign.digest().as_str()
        ));
        Ok(Self {
            scope_digest: scope.digest(),
            campaign_digest: campaign.digest(),
            request_digest,
            path_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn campaign_digest(&self) -> &Digest {
        &self.campaign_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "POST {PERSONALIZE_OPERATION_PATH}?target={DESCRIBE_CAMPAIGN_TARGET}&campaignDigest={}",
            self.campaign_digest.as_str()
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsPersonalizeOperation::DescribeCampaign,
            scope_digest: self.scope_digest.clone(),
            target_digest: Some(self.campaign_digest.clone()),
            filter_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeRecommenderRequest {
    scope_digest: Digest,
    recommender_digest: Digest,
    request_digest: Digest,
    path_digest: Digest,
}

impl DescribeRecommenderRequest {
    pub fn for_scope(scope: &AwsPersonalizeRecommendationScope) -> Result<Self> {
        let recommender = scope
            .recommender()
            .ok_or(AwsPersonalizeRecommendationError::UnsupportedOperation)?;
        let request_digest = Digest::from_parts(
            "aws-personalize-describe-recommender-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("recommender", recommender.digest().as_str().to_owned()),
            ],
        );
        let path_digest = Digest::from_text(format!(
            "POST {PERSONALIZE_OPERATION_PATH} {DESCRIBE_RECOMMENDER_TARGET} recommender={}",
            recommender.digest().as_str()
        ));
        Ok(Self {
            scope_digest: scope.digest(),
            recommender_digest: recommender.digest(),
            request_digest,
            path_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn recommender_digest(&self) -> &Digest {
        &self.recommender_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "POST {PERSONALIZE_OPERATION_PATH}?target={DESCRIBE_RECOMMENDER_TARGET}&recommenderDigest={}",
            self.recommender_digest.as_str()
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsPersonalizeOperation::DescribeRecommender,
            scope_digest: self.scope_digest.clone(),
            target_digest: Some(self.recommender_digest.clone()),
            filter_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRecommendationsRequest {
    scope_digest: Digest,
    target: ServingTarget,
    target_digest: Digest,
    user_fingerprint: Option<UserFingerprint>,
    item_fingerprint: Option<ItemFingerprint>,
    filter: Option<FilterIdentity>,
    num_results: u16,
    request_digest: Digest,
    path_digest: Digest,
}

impl GetRecommendationsRequest {
    pub fn for_scope(scope: &AwsPersonalizeRecommendationScope, num_results: u16) -> Result<Self> {
        let target = if scope.campaign().is_some() {
            ServingTarget::Campaign
        } else {
            ServingTarget::Recommender
        };
        Self::for_scope_with_target(scope, target, num_results)
    }

    pub fn for_scope_with_target(
        scope: &AwsPersonalizeRecommendationScope,
        target: ServingTarget,
        num_results: u16,
    ) -> Result<Self> {
        if num_results == 0 || num_results > MAX_RESULTS {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        let target_digest = match target {
            ServingTarget::Campaign => scope
                .campaign()
                .ok_or(AwsPersonalizeRecommendationError::ScopeMismatch)?
                .digest(),
            ServingTarget::Recommender => scope
                .recommender()
                .ok_or(AwsPersonalizeRecommendationError::ScopeMismatch)?
                .digest(),
        };
        Self::new(
            scope,
            target,
            target_digest,
            scope.user_fingerprint().cloned(),
            scope.item_fingerprint().cloned(),
            scope.filter().cloned(),
            num_results,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsPersonalizeRecommendationScope,
        target: ServingTarget,
        target_digest: Digest,
        user_fingerprint: Option<UserFingerprint>,
        item_fingerprint: Option<ItemFingerprint>,
        filter: Option<FilterIdentity>,
        num_results: u16,
    ) -> Result<Self> {
        if num_results == 0 || num_results > MAX_RESULTS {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        let expected_target_digest = match target {
            ServingTarget::Campaign => scope
                .campaign()
                .ok_or(AwsPersonalizeRecommendationError::ScopeMismatch)?
                .digest(),
            ServingTarget::Recommender => scope
                .recommender()
                .ok_or(AwsPersonalizeRecommendationError::ScopeMismatch)?
                .digest(),
        };
        if target_digest != expected_target_digest
            || user_fingerprint != scope.user_fingerprint().cloned()
            || item_fingerprint != scope.item_fingerprint().cloned()
            || filter != scope.filter().cloned()
        {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        if user_fingerprint.is_none() && item_fingerprint.is_none() {
            return Err(AwsPersonalizeRecommendationError::InvalidScope);
        }
        let request_digest = Digest::from_parts(
            "aws-personalize-get-recommendations-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("target", target.as_str().to_owned()),
                ("target_digest", target_digest.as_str().to_owned()),
                (
                    "user",
                    user_fingerprint
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "item",
                    item_fingerprint
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "filter",
                    filter
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("num_results", num_results.to_string()),
            ],
        );
        let path_digest = Digest::from_text(format!(
            "POST {PERSONALIZE_OPERATION_PATH} {GET_RECOMMENDATIONS_TARGET} target={target:?} targetDigest={} userDigest={} itemDigest={} filterDigest={} numResults={num_results}",
            target_digest.as_str(),
            user_fingerprint.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
            item_fingerprint.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
            filter.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
        ));
        Ok(Self {
            scope_digest: scope.digest(),
            target,
            target_digest,
            user_fingerprint,
            item_fingerprint,
            filter,
            num_results,
            request_digest,
            path_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn target(&self) -> ServingTarget {
        self.target
    }

    pub fn target_digest(&self) -> &Digest {
        &self.target_digest
    }

    pub fn user_fingerprint(&self) -> Option<&UserFingerprint> {
        self.user_fingerprint.as_ref()
    }

    pub fn item_fingerprint(&self) -> Option<&ItemFingerprint> {
        self.item_fingerprint.as_ref()
    }

    pub fn filter(&self) -> Option<&FilterIdentity> {
        self.filter.as_ref()
    }

    pub const fn num_results(&self) -> u16 {
        self.num_results
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "POST {PERSONALIZE_OPERATION_PATH}?target={GET_RECOMMENDATIONS_TARGET}&targetDigest={}&userDigest={}&itemDigest={}&filterDigest={}&numResults={}",
            self.target_digest.as_str(),
            self.user_fingerprint.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
            self.item_fingerprint.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
            self.filter.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
            self.num_results
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsPersonalizeOperation::GetRecommendations,
            scope_digest: self.scope_digest.clone(),
            target_digest: Some(self.target_digest.clone()),
            filter_digest: self.filter.as_ref().map(FilterIdentity::digest),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPersonalizedRankingRequest {
    scope_digest: Digest,
    target: ServingTarget,
    target_digest: Digest,
    user_fingerprint: UserFingerprint,
    item_fingerprint: ItemFingerprint,
    filter: Option<FilterIdentity>,
    num_results: u16,
    request_digest: Digest,
    path_digest: Digest,
}

impl GetPersonalizedRankingRequest {
    pub fn for_scope(scope: &AwsPersonalizeRecommendationScope, num_results: u16) -> Result<Self> {
        Self::for_scope_with_target(scope, ServingTarget::Campaign, num_results)
    }

    pub fn for_scope_with_target(
        scope: &AwsPersonalizeRecommendationScope,
        target: ServingTarget,
        num_results: u16,
    ) -> Result<Self> {
        if target != ServingTarget::Campaign {
            return Err(AwsPersonalizeRecommendationError::UnsupportedOperation);
        }
        let target_digest = scope
            .campaign()
            .ok_or(AwsPersonalizeRecommendationError::ScopeMismatch)?
            .digest();
        let user_fingerprint = scope
            .user_fingerprint()
            .cloned()
            .ok_or(AwsPersonalizeRecommendationError::InvalidScope)?;
        let item_fingerprint = scope
            .item_fingerprint()
            .cloned()
            .ok_or(AwsPersonalizeRecommendationError::InvalidScope)?;
        Self::new(
            scope,
            target,
            target_digest,
            user_fingerprint,
            item_fingerprint,
            scope.filter().cloned(),
            num_results,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsPersonalizeRecommendationScope,
        target: ServingTarget,
        target_digest: Digest,
        user_fingerprint: UserFingerprint,
        item_fingerprint: ItemFingerprint,
        filter: Option<FilterIdentity>,
        num_results: u16,
    ) -> Result<Self> {
        if target != ServingTarget::Campaign {
            return Err(AwsPersonalizeRecommendationError::UnsupportedOperation);
        }
        if num_results == 0 || num_results > MAX_RESULTS {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        let expected_target_digest = scope
            .campaign()
            .ok_or(AwsPersonalizeRecommendationError::ScopeMismatch)?
            .digest();
        if target_digest != expected_target_digest
            || Some(user_fingerprint.clone()) != scope.user_fingerprint().cloned()
            || Some(item_fingerprint.clone()) != scope.item_fingerprint().cloned()
            || filter != scope.filter().cloned()
        {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        let request_digest = Digest::from_parts(
            "aws-personalize-get-personalized-ranking-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("target", target.as_str().to_owned()),
                ("target_digest", target_digest.as_str().to_owned()),
                ("user", user_fingerprint.digest().as_str().to_owned()),
                ("item", item_fingerprint.digest().as_str().to_owned()),
                (
                    "filter",
                    filter
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("num_results", num_results.to_string()),
            ],
        );
        let path_digest = Digest::from_text(format!(
            "POST {PERSONALIZE_OPERATION_PATH} {GET_PERSONALIZED_RANKING_TARGET} targetDigest={} userDigest={} itemDigest={} filterDigest={} numResults={num_results}",
            target_digest.as_str(),
            user_fingerprint.digest().as_str(),
            item_fingerprint.digest().as_str(),
            filter.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
        ));
        Ok(Self {
            scope_digest: scope.digest(),
            target,
            target_digest,
            user_fingerprint,
            item_fingerprint,
            filter,
            num_results,
            request_digest,
            path_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn target(&self) -> ServingTarget {
        self.target
    }

    pub fn target_digest(&self) -> &Digest {
        &self.target_digest
    }

    pub fn user_fingerprint(&self) -> &UserFingerprint {
        &self.user_fingerprint
    }

    pub fn item_fingerprint(&self) -> &ItemFingerprint {
        &self.item_fingerprint
    }

    pub fn filter(&self) -> Option<&FilterIdentity> {
        self.filter.as_ref()
    }

    pub const fn num_results(&self) -> u16 {
        self.num_results
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "POST {PERSONALIZE_OPERATION_PATH}?target={GET_PERSONALIZED_RANKING_TARGET}&targetDigest={}&userDigest={}&itemDigest={}&filterDigest={}&numResults={}",
            self.target_digest.as_str(),
            self.user_fingerprint.digest().as_str(),
            self.item_fingerprint.digest().as_str(),
            self.filter.as_ref().map_or_else(
                || "none".to_owned(),
                |value| value.digest().as_str().to_owned()
            ),
            self.num_results
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsPersonalizeOperation::GetPersonalizedRanking,
            scope_digest: self.scope_digest.clone(),
            target_digest: Some(self.target_digest.clone()),
            filter_digest: self.filter.as_ref().map(FilterIdentity::digest),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeCampaignResponse {
    pub request_digest: Digest,
    pub metadata: CampaignMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl DescribeCampaignResponse {
    pub fn new(
        request: &DescribeCampaignRequest,
        metadata: CampaignMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        metadata.validate_digest()?;
        if response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
            || metadata.campaign_digest != request.campaign_digest
        {
            return Err(AwsPersonalizeRecommendationError::PartialEvidence);
        }
        let response_digest = Digest::from_parts(
            "aws-personalize-describe-campaign-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("metadata", metadata.metadata_digest.as_str().to_owned()),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            metadata,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub(crate) fn validate_integrity(&self, request: &DescribeCampaignRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.metadata.campaign_digest != request.campaign_digest
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        let rebuilt = Self::new(
            request,
            self.metadata.clone(),
            self.response_bytes,
            self.provenance,
        )?;
        if rebuilt.response_digest != self.response_digest {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeRecommenderResponse {
    pub request_digest: Digest,
    pub metadata: RecommenderMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl DescribeRecommenderResponse {
    pub fn new(
        request: &DescribeRecommenderRequest,
        metadata: RecommenderMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        metadata.validate_digest()?;
        if response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
            || metadata.recommender_digest != request.recommender_digest
        {
            return Err(AwsPersonalizeRecommendationError::PartialEvidence);
        }
        let response_digest = Digest::from_parts(
            "aws-personalize-describe-recommender-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("metadata", metadata.metadata_digest.as_str().to_owned()),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            metadata,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub(crate) fn validate_integrity(&self, request: &DescribeRecommenderRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.metadata.recommender_digest != request.recommender_digest
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        let rebuilt = Self::new(
            request,
            self.metadata.clone(),
            self.response_bytes,
            self.provenance,
        )?;
        if rebuilt.response_digest != self.response_digest {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRecommendationsResponse {
    pub request_digest: Digest,
    pub result: RecommendationResult,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl GetRecommendationsResponse {
    pub fn new(
        request: &GetRecommendationsRequest,
        result: RecommendationResult,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
            || result.operation != RecommendationOperation::GetRecommendations
            || result.items.len() > request.num_results as usize
        {
            return Err(AwsPersonalizeRecommendationError::PartialEvidence);
        }
        result.validate()?;
        let response_digest = Digest::from_parts(
            "aws-personalize-get-recommendations-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("result", result.result_digest.as_str().to_owned()),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            result,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub(crate) fn validate_integrity(&self, request: &GetRecommendationsRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        let rebuilt = Self::new(
            request,
            self.result.clone(),
            self.response_bytes,
            self.provenance,
        )?;
        if rebuilt.response_digest != self.response_digest {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPersonalizedRankingResponse {
    pub request_digest: Digest,
    pub result: RecommendationResult,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl GetPersonalizedRankingResponse {
    pub fn new(
        request: &GetPersonalizedRankingRequest,
        result: RecommendationResult,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
            || result.operation != RecommendationOperation::GetPersonalizedRanking
            || result.items.len() > request.num_results as usize
        {
            return Err(AwsPersonalizeRecommendationError::PartialEvidence);
        }
        result.validate()?;
        let response_digest = Digest::from_parts(
            "aws-personalize-get-personalized-ranking-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("result", result.result_digest.as_str().to_owned()),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            result,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub(crate) fn validate_integrity(&self, request: &GetPersonalizedRankingRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        let rebuilt = Self::new(
            request,
            self.result.clone(),
            self.response_bytes,
            self.provenance,
        )?;
        if rebuilt.response_digest != self.response_digest {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AwsPersonalizeProvider<T> {
    transport: T,
    definition: AwsPersonalizeProviderDefinition,
}

impl<T> AwsPersonalizeProvider<T>
where
    T: AwsPersonalizeTransport,
{
    pub fn new(transport: T) -> Result<Self> {
        Self::with_definition(transport, AwsPersonalizeProviderDefinition::new())
    }

    pub fn with_definition(
        transport: T,
        definition: AwsPersonalizeProviderDefinition,
    ) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsPersonalizeProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_campaign(
        &mut self,
        request: &DescribeCampaignRequest,
    ) -> std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError> {
        let response = self.transport.describe_campaign(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        Ok(response)
    }

    pub fn describe_recommender(
        &mut self,
        request: &DescribeRecommenderRequest,
    ) -> std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError> {
        let response = self.transport.describe_recommender(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        Ok(response)
    }

    pub fn get_recommendations(
        &mut self,
        request: &GetRecommendationsRequest,
    ) -> std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError> {
        let response = self.transport.get_recommendations(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        Ok(response)
    }

    pub fn get_personalized_ranking(
        &mut self,
        request: &GetPersonalizedRankingRequest,
    ) -> std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError> {
        let response = self.transport.get_personalized_ranking(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        Ok(response)
    }
}

impl<T> Default for AwsPersonalizeProvider<T>
where
    T: AwsPersonalizeTransport + Default,
{
    fn default() -> Self {
        Self::new(T::default()).expect("default Personalize provider definition is valid")
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    describe_campaign:
        VecDeque<std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError>>,
    describe_recommender:
        VecDeque<std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError>>,
    get_recommendations:
        VecDeque<std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError>>,
    get_personalized_ranking:
        VecDeque<std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn push_describe_campaign_response(
        &mut self,
        response: std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError>,
    ) {
        self.describe_campaign.push_back(response);
    }

    pub fn push_describe_recommender_response(
        &mut self,
        response: std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError>,
    ) {
        self.describe_recommender.push_back(response);
    }

    pub fn push_get_recommendations_response(
        &mut self,
        response: std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError>,
    ) {
        self.get_recommendations.push_back(response);
    }

    pub fn push_get_personalized_ranking_response(
        &mut self,
        response: std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError>,
    ) {
        self.get_personalized_ranking.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn pop<T>(
        queue: &mut VecDeque<std::result::Result<T, AwsPersonalizeTransportError>>,
    ) -> std::result::Result<T, AwsPersonalizeTransportError> {
        queue
            .pop_front()
            .unwrap_or(Err(AwsPersonalizeTransportError::InvalidResponse))
    }
}

impl AwsPersonalizeTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn describe_campaign(
        &mut self,
        request: &DescribeCampaignRequest,
    ) -> std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError> {
        self.requests.push(request.recorded_request());
        Self::pop(&mut self.describe_campaign)
    }

    fn describe_recommender(
        &mut self,
        request: &DescribeRecommenderRequest,
    ) -> std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError> {
        self.requests.push(request.recorded_request());
        Self::pop(&mut self.describe_recommender)
    }

    fn get_recommendations(
        &mut self,
        request: &GetRecommendationsRequest,
    ) -> std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError> {
        self.requests.push(request.recorded_request());
        Self::pop(&mut self.get_recommendations)
    }

    fn get_personalized_ranking(
        &mut self,
        request: &GetPersonalizedRankingRequest,
    ) -> std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError> {
        self.requests.push(request.recorded_request());
        Self::pop(&mut self.get_personalized_ranking)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsPersonalizeRecommendationScope,
    observed_at: DateTime<Utc>,
    provenance: TransportProvenance,
}

impl FixtureTransport {
    pub fn for_scope(
        scope: &AwsPersonalizeRecommendationScope,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self::with_provenance(scope, observed_at, TransportProvenance::Fixture)
    }

    fn with_provenance(
        scope: &AwsPersonalizeRecommendationScope,
        observed_at: DateTime<Utc>,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
            provenance,
        }
    }

    fn ensure_scope(
        &self,
        digest: &Digest,
    ) -> std::result::Result<(), AwsPersonalizeTransportError> {
        if *digest == self.scope.digest() {
            Ok(())
        } else {
            Err(AwsPersonalizeTransportError::InvalidResponse)
        }
    }

    fn model_revision(&self) -> ModelRevision {
        ModelRevision::from_digest(
            Digest::from_text("fixture-model-revision-1"),
            self.scope
                .solution_version()
                .map(SolutionVersionIdentity::digest),
        )
        .expect("fixture model revision")
    }

    fn result(operation: RecommendationOperation, limit: u16) -> Result<RecommendationResult> {
        let fixtures = [
            (RecommendationItemKind::Item, "fixture-item-001", 0.93),
            (RecommendationItemKind::Item, "fixture-item-002", 0.67),
            (RecommendationItemKind::Action, "fixture-action-003", 0.22),
        ];
        let items = fixtures
            .into_iter()
            .take(limit as usize)
            .enumerate()
            .map(|(index, (kind, identifier, score))| {
                RecommendationItem::new(kind, identifier, index as u16 + 1, Some(score))
            })
            .collect::<Result<Vec<_>>>()?;
        RecommendationResult::new(operation, items)
    }
}

impl AwsPersonalizeTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_campaign(
        &mut self,
        request: &DescribeCampaignRequest,
    ) -> std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError> {
        self.ensure_scope(request.scope_digest())?;
        let metadata = CampaignMetadata::new(
            &self.scope,
            CampaignMetadataInput {
                status: CampaignStatus::Active,
                model_revision: self.model_revision(),
                failure_reason: None,
                observed_at: self.observed_at,
            },
        )
        .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        DescribeCampaignResponse::new(request, metadata, 512, self.provenance)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)
    }

    fn describe_recommender(
        &mut self,
        request: &DescribeRecommenderRequest,
    ) -> std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError> {
        self.ensure_scope(request.scope_digest())?;
        let metadata = RecommenderMetadata::new(
            &self.scope,
            RecommenderMetadataInput {
                status: RecommenderStatus::Active,
                model_revision: self.model_revision(),
                failure_reason: None,
                observed_at: self.observed_at,
            },
        )
        .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        DescribeRecommenderResponse::new(request, metadata, 512, self.provenance)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)
    }

    fn get_recommendations(
        &mut self,
        request: &GetRecommendationsRequest,
    ) -> std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError> {
        self.ensure_scope(request.scope_digest())?;
        let result = Self::result(
            RecommendationOperation::GetRecommendations,
            request.num_results(),
        )
        .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        GetRecommendationsResponse::new(request, result, 768, self.provenance)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)
    }

    fn get_personalized_ranking(
        &mut self,
        request: &GetPersonalizedRankingRequest,
    ) -> std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError> {
        self.ensure_scope(request.scope_digest())?;
        let result = Self::result(
            RecommendationOperation::GetPersonalizedRanking,
            request.num_results(),
        )
        .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)?;
        GetPersonalizedRankingResponse::new(request, result, 768, self.provenance)
            .map_err(|_| AwsPersonalizeTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(
        scope: &AwsPersonalizeRecommendationScope,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            fixture: FixtureTransport::with_provenance(
                scope,
                observed_at,
                TransportProvenance::Loopback,
            ),
        }
    }
}

impl AwsPersonalizeTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_campaign(
        &mut self,
        request: &DescribeCampaignRequest,
    ) -> std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError> {
        self.fixture.describe_campaign(request)
    }

    fn describe_recommender(
        &mut self,
        request: &DescribeRecommenderRequest,
    ) -> std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError> {
        self.fixture.describe_recommender(request)
    }

    fn get_recommendations(
        &mut self,
        request: &GetRecommendationsRequest,
    ) -> std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError> {
        self.fixture.get_recommendations(request)
    }

    fn get_personalized_ranking(
        &mut self,
        request: &GetPersonalizedRankingRequest,
    ) -> std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError> {
        self.fixture.get_personalized_ranking(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsPersonalizeTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_campaign(
        &mut self,
        _request: &DescribeCampaignRequest,
    ) -> std::result::Result<DescribeCampaignResponse, AwsPersonalizeTransportError> {
        Err(AwsPersonalizeTransportError::BlockedEnv)
    }

    fn describe_recommender(
        &mut self,
        _request: &DescribeRecommenderRequest,
    ) -> std::result::Result<DescribeRecommenderResponse, AwsPersonalizeTransportError> {
        Err(AwsPersonalizeTransportError::BlockedEnv)
    }

    fn get_recommendations(
        &mut self,
        _request: &GetRecommendationsRequest,
    ) -> std::result::Result<GetRecommendationsResponse, AwsPersonalizeTransportError> {
        Err(AwsPersonalizeTransportError::BlockedEnv)
    }

    fn get_personalized_ranking(
        &mut self,
        _request: &GetPersonalizedRankingRequest,
    ) -> std::result::Result<GetPersonalizedRankingResponse, AwsPersonalizeTransportError> {
        Err(AwsPersonalizeTransportError::BlockedEnv)
    }
}

pub type AwsPersonalizeProviderResult<T> = AwsPersonalizeProvider<T>;
