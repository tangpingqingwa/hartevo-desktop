//! Bounded AWS Entity Resolution provider seams.
//!
//! This module intentionally contains no AWS SDK, SigV4 signer, credential
//! resolver, HTTP client, matching job, identity-map, or S3 output path.

use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{AwsEntityResolutionError, AwsEntityResolutionTransportError, Result};
use crate::model::{
    AwsEntityResolutionScope, Digest, IdNamespaceMetadata, MatchingWorkflowMetadata,
    SchemaMappingMetadata, SourceRecordFingerprint, TransportProvenance,
};
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_REVISION,
};

pub const LIST_ID_NAMESPACES_OPERATION_PATH: &str = "/idnamespaces";
pub const GET_ID_NAMESPACE_OPERATION_PATH: &str = "/idnamespaces/{idNamespaceName}";
pub const GET_MATCHING_WORKFLOW_OPERATION_PATH: &str = "/matchingworkflows/{workflowName}";
pub const GET_SCHEMA_MAPPING_OPERATION_PATH: &str = "/schemamappings/{schemaName}";
pub const GET_MATCH_ID_OPERATION_PATH: &str = "/matchingworkflows/{workflowName}/matches";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsEntityResolutionOperation {
    ListIdNamespaces,
    GetIdNamespace,
    GetMatchingWorkflow,
    GetSchemaMapping,
    GetMatchId,
}

impl AwsEntityResolutionOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListIdNamespaces => "ListIdNamespaces",
            Self::GetIdNamespace => "GetIdNamespace",
            Self::GetMatchingWorkflow => "GetMatchingWorkflow",
            Self::GetSchemaMapping => "GetSchemaMapping",
            Self::GetMatchId => "GetMatchId",
        }
    }
}

/// The only provider transport trait exposed by this Layer-1 crate.
pub trait AwsEntityResolutionTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_id_namespaces(
        &mut self,
        request: &ListIdNamespacesRequest,
    ) -> std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError>;

    fn get_id_namespace(
        &mut self,
        request: &GetIdNamespaceRequest,
    ) -> std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError>;

    fn get_matching_workflow(
        &mut self,
        request: &GetMatchingWorkflowRequest,
    ) -> std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError>;

    fn get_schema_mapping(
        &mut self,
        request: &GetSchemaMappingRequest,
    ) -> std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError>;

    fn get_match_id(
        &mut self,
        request: &GetMatchIdRequest,
    ) -> std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsEntityResolutionOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub payload_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListIdNamespacesRequest {
    scope_digest: Digest,
    account_path: String,
    region_path: String,
    page_number: u16,
    max_results: u16,
    next_token_digest: Option<Digest>,
    request_digest: Digest,
}

impl ListIdNamespacesRequest {
    pub fn new(
        scope: &AwsEntityResolutionScope,
        max_results: u16,
        page_number: u16,
        next_token_digest: Option<Digest>,
    ) -> Result<Self> {
        scope.validate()?;
        if max_results == 0
            || max_results > MAX_PAGE_SIZE
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(AwsEntityResolutionError::InvalidRequest);
        }
        if let Some(token) = &next_token_digest {
            token.validate()?;
        }
        let scope_digest = scope.digest();
        let request_digest = Digest::from_parts(
            "aws-entity-resolution-list-id-namespaces-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
                ("max_results", max_results.to_string()),
                (
                    "next_token",
                    next_token_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            scope_digest,
            account_path: scope.account().as_str().to_owned(),
            region_path: scope.region().as_str().to_owned(),
            page_number,
            max_results,
            next_token_digest,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn next_token_digest(&self) -> Option<&Digest> {
        self.next_token_digest.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        let mut path = format!(
            "{LIST_ID_NAMESPACES_OPERATION_PATH}?awsAccountId={}&region={}&maxResults={}&page={}",
            self.account_path, self.region_path, self.max_results, self.page_number
        );
        if let Some(token) = &self.next_token_digest {
            path.push_str("&nextTokenDigest=");
            path.push_str(token.as_str());
        }
        path
    }
}

impl fmt::Debug for ListIdNamespacesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListIdNamespacesRequest")
            .field("scope_digest", &self.scope_digest)
            .field("page_number", &self.page_number)
            .field("max_results", &self.max_results)
            .field("next_token_digest", &self.next_token_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

macro_rules! resource_request {
    ($name:ident, $field:ident, $operation:expr, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            scope_digest: Digest,
            resource: crate::model::ResourceIdentity,
            request_digest: Digest,
        }

        impl $name {
            pub fn for_scope(scope: &AwsEntityResolutionScope) -> Result<Self> {
                scope.validate()?;
                let resource = scope.$field().clone();
                let scope_digest = scope.digest();
                let request_digest = Digest::from_parts(
                    $domain,
                    &[
                        ("scope", scope_digest.as_str().to_owned()),
                        ("resource", resource.digest().as_str().to_owned()),
                    ],
                );
                Ok(Self {
                    scope_digest,
                    resource,
                    request_digest,
                })
            }

            pub fn scope_digest(&self) -> &Digest {
                &self.scope_digest
            }

            pub fn resource(&self) -> &crate::model::ResourceIdentity {
                &self.resource
            }

            pub fn request_digest(&self) -> &Digest {
                &self.request_digest
            }

            pub fn path(&self) -> String {
                format!(
                    "{}?resourceNameDigest={}",
                    $operation,
                    self.resource.digest().as_str()
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("scope_digest", &self.scope_digest)
                    .field("resource", &self.resource)
                    .field("request_digest", &self.request_digest)
                    .finish()
            }
        }
    };
}

resource_request!(
    GetIdNamespaceRequest,
    id_namespace,
    GET_ID_NAMESPACE_OPERATION_PATH,
    "aws-entity-resolution-get-id-namespace-request/v1"
);
resource_request!(
    GetMatchingWorkflowRequest,
    matching_workflow,
    GET_MATCHING_WORKFLOW_OPERATION_PATH,
    "aws-entity-resolution-get-matching-workflow-request/v1"
);
resource_request!(
    GetSchemaMappingRequest,
    schema_mapping,
    GET_SCHEMA_MAPPING_OPERATION_PATH,
    "aws-entity-resolution-get-schema-mapping-request/v1"
);

#[derive(Clone, Eq, PartialEq)]
pub struct GetMatchIdRequest {
    scope_digest: Digest,
    workflow: crate::model::ResourceIdentity,
    source_record_fingerprint: SourceRecordFingerprint,
    apply_normalization: bool,
    request_digest: Digest,
}

impl GetMatchIdRequest {
    pub fn for_scope(scope: &AwsEntityResolutionScope, apply_normalization: bool) -> Result<Self> {
        scope.validate()?;
        if scope.source_record_fingerprint().apply_normalization != apply_normalization {
            return Err(AwsEntityResolutionError::ScopeMismatch);
        }
        let scope_digest = scope.digest();
        let workflow = scope.matching_workflow().clone();
        let source_record_fingerprint = scope.source_record_fingerprint().clone();
        let request_digest = Digest::from_parts(
            "aws-entity-resolution-get-match-id-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("workflow", workflow.digest().as_str().to_owned()),
                (
                    "record",
                    source_record_fingerprint.digest().as_str().to_owned(),
                ),
                ("normalization", apply_normalization.to_string()),
            ],
        );
        Ok(Self {
            scope_digest,
            workflow,
            source_record_fingerprint,
            apply_normalization,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn workflow(&self) -> &crate::model::ResourceIdentity {
        &self.workflow
    }

    pub fn source_record_fingerprint(&self) -> &SourceRecordFingerprint {
        &self.source_record_fingerprint
    }

    pub const fn apply_normalization(&self) -> bool {
        self.apply_normalization
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path(&self) -> String {
        format!(
            "{GET_MATCH_ID_OPERATION_PATH}?workflowNameDigest={}",
            self.workflow.digest().as_str()
        )
    }
}

impl fmt::Debug for GetMatchIdRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetMatchIdRequest")
            .field("scope_digest", &self.scope_digest)
            .field("workflow", &self.workflow)
            .field("source_record_fingerprint", &self.source_record_fingerprint)
            .field("apply_normalization", &self.apply_normalization)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListIdNamespacesResponse {
    pub request_digest: Digest,
    pub namespaces: Vec<IdNamespaceMetadata>,
    pub next_token_digest: Option<Digest>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl ListIdNamespacesResponse {
    pub fn new(
        request: &ListIdNamespacesRequest,
        namespaces: Vec<IdNamespaceMetadata>,
        next_token_digest: Option<Digest>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if namespaces.len() > request.max_results() as usize
            || response_bytes > MAX_RESPONSE_BYTES
            || response_bytes == 0
        {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        for namespace in &namespaces {
            namespace.validate()?;
        }
        if let Some(token) = &next_token_digest {
            token.validate()?;
        }
        let response_digest =
            list_response_digest(request, &namespaces, next_token_digest.as_ref());
        Ok(Self {
            request_digest: request.request_digest().clone(),
            namespaces,
            next_token_digest,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub(crate) fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn validate_integrity(&self, request: &ListIdNamespacesRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.namespaces.len() > request.max_results() as usize
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.response_digest
                != list_response_digest(request, &self.namespaces, self.next_token_digest.as_ref())
        {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        for namespace in &self.namespaces {
            namespace.validate()?;
        }
        Ok(())
    }
}

macro_rules! metadata_response {
    ($name:ident, $request:ty, $metadata:ty, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub request_digest: Digest,
            pub metadata: $metadata,
            pub response_bytes: u64,
            pub provenance: TransportProvenance,
            pub response_digest: Digest,
        }

        impl $name {
            pub fn new(
                request: &$request,
                metadata: $metadata,
                response_bytes: u64,
                provenance: TransportProvenance,
            ) -> Result<Self> {
                if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
                    return Err(AwsEntityResolutionError::InvalidMetadata);
                }
                metadata.validate()?;
                let response_digest = Digest::from_parts(
                    $domain,
                    &[
                        ("request", request.request_digest().as_str().to_owned()),
                        ("metadata", metadata.metadata_digest.as_str().to_owned()),
                        ("bytes", response_bytes.to_string()),
                    ],
                );
                Ok(Self {
                    request_digest: request.request_digest().clone(),
                    metadata,
                    response_bytes,
                    provenance,
                    response_digest,
                })
            }

            pub(crate) fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
                self.provenance = provenance;
                self
            }

            pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
                self.response_digest = response_digest;
                self
            }

            pub fn validate_integrity(&self, request: &$request) -> Result<()> {
                let expected = Digest::from_parts(
                    $domain,
                    &[
                        ("request", request.request_digest().as_str().to_owned()),
                        (
                            "metadata",
                            self.metadata.metadata_digest.as_str().to_owned(),
                        ),
                        ("bytes", self.response_bytes.to_string()),
                    ],
                );
                if self.request_digest != *request.request_digest()
                    || self.response_bytes == 0
                    || self.response_bytes > MAX_RESPONSE_BYTES
                    || self.provenance.is_native()
                    || self.provenance.is_connected()
                    || self.provenance.is_first_party()
                    || self.response_digest != expected
                {
                    return Err(AwsEntityResolutionError::TamperedEvidence);
                }
                self.metadata.validate()
            }
        }
    };
}

metadata_response!(
    IdNamespaceResponse,
    GetIdNamespaceRequest,
    IdNamespaceMetadata,
    "aws-entity-resolution-id-namespace-response/v1"
);
metadata_response!(
    MatchingWorkflowResponse,
    GetMatchingWorkflowRequest,
    MatchingWorkflowMetadata,
    "aws-entity-resolution-matching-workflow-response/v1"
);
metadata_response!(
    SchemaMappingResponse,
    GetSchemaMappingRequest,
    SchemaMappingMetadata,
    "aws-entity-resolution-schema-mapping-response/v1"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMatchIdResponse {
    pub request_digest: Digest,
    pub status: crate::model::MatchStatus,
    pub match_group_digest: Option<Digest>,
    pub match_rule_digest: Option<Digest>,
    pub result_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl GetMatchIdResponse {
    pub fn new(
        request: &GetMatchIdRequest,
        status: crate::model::MatchStatus,
        match_group_digest: Option<Digest>,
        match_rule_digest: Option<Digest>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        if matches!(status, crate::model::MatchStatus::Matched)
            && (match_group_digest.is_none() || match_rule_digest.is_none())
        {
            return Err(AwsEntityResolutionError::InvalidResponse);
        }
        if let Some(digest) = &match_group_digest {
            digest.validate()?;
        }
        if let Some(digest) = &match_rule_digest {
            digest.validate()?;
        }
        let result_digest = result_digest(
            request,
            status,
            match_group_digest.as_ref(),
            match_rule_digest.as_ref(),
        );
        let response_digest = match_response_digest(request, &result_digest, response_bytes);
        Ok(Self {
            request_digest: request.request_digest().clone(),
            status,
            match_group_digest,
            match_rule_digest,
            result_digest,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    /// Fixture helper: the seed is hashed immediately and is not retained.
    pub fn matched(
        request: &GetMatchIdRequest,
        group_seed: impl AsRef<str>,
        rule_seed: impl AsRef<str>,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let group_digest = Digest::from_parts(
            "aws-entity-resolution-match-group/v1",
            &[("seed", group_seed.as_ref().to_owned())],
        );
        let rule_digest = Digest::from_parts(
            "aws-entity-resolution-match-rule/v1",
            &[("seed", rule_seed.as_ref().to_owned())],
        );
        Self::new(
            request,
            crate::model::MatchStatus::Matched,
            Some(group_digest),
            Some(rule_digest),
            256,
            provenance,
        )
    }

    pub(crate) fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetMatchIdRequest) -> Result<()> {
        let expected_result = result_digest(
            request,
            self.status,
            self.match_group_digest.as_ref(),
            self.match_rule_digest.as_ref(),
        );
        let expected_response =
            match_response_digest(request, &expected_result, self.response_bytes);
        if self.request_digest != *request.request_digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.result_digest != expected_result
            || self.response_digest != expected_response
        {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        if let Some(digest) = &self.match_group_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.match_rule_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

fn list_response_digest(
    request: &ListIdNamespacesRequest,
    namespaces: &[IdNamespaceMetadata],
    next_token_digest: Option<&Digest>,
) -> Digest {
    Digest::from_parts(
        "aws-entity-resolution-list-id-namespaces-response/v1",
        &[
            ("request", request.request_digest().as_str().to_owned()),
            (
                "namespaces",
                namespaces
                    .iter()
                    .map(|namespace| namespace.metadata_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "next_token",
                next_token_digest.map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
        ],
    )
}

fn result_digest(
    request: &GetMatchIdRequest,
    status: crate::model::MatchStatus,
    match_group_digest: Option<&Digest>,
    match_rule_digest: Option<&Digest>,
) -> Digest {
    Digest::from_parts(
        "aws-entity-resolution-match-result/v1",
        &[
            ("request", request.request_digest().as_str().to_owned()),
            ("status", format!("{status:?}")),
            (
                "group",
                match_group_digest.map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "rule",
                match_rule_digest.map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
        ],
    )
}

fn match_response_digest(
    request: &GetMatchIdRequest,
    result_digest: &Digest,
    response_bytes: u64,
) -> Digest {
    Digest::from_parts(
        "aws-entity-resolution-get-match-id-response/v1",
        &[
            ("request", request.request_digest().as_str().to_owned()),
            ("result", result_digest.as_str().to_owned()),
            ("bytes", response_bytes.to_string()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEntityResolutionProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub operations: Vec<AwsEntityResolutionOperation>,
    pub allowed_provenance: Vec<TransportProvenance>,
    pub connected_evidence: bool,
    pub native_evidence: bool,
    pub first_party_evidence: bool,
    pub provider_receipt: bool,
}

impl AwsEntityResolutionProviderDefinition {
    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision != PROVIDER_REVISION
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release != PLUGIN_VERSION
            || self.operations
                != vec![
                    AwsEntityResolutionOperation::ListIdNamespaces,
                    AwsEntityResolutionOperation::GetIdNamespace,
                    AwsEntityResolutionOperation::GetMatchingWorkflow,
                    AwsEntityResolutionOperation::GetSchemaMapping,
                    AwsEntityResolutionOperation::GetMatchId,
                ]
            || self.allowed_provenance
                != vec![
                    TransportProvenance::Recording,
                    TransportProvenance::Fixture,
                    TransportProvenance::Loopback,
                    TransportProvenance::BlockedEnv,
                ]
            || self.connected_evidence
            || self.native_evidence
            || self.first_party_evidence
            || self.provider_receipt
        {
            return Err(AwsEntityResolutionError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-entity-resolution-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        if self.capability_digest != capability_digest {
            return Err(AwsEntityResolutionError::ProviderDrift);
        }
        let expected = Digest::from_parts(
            "aws-entity-resolution-provider/v1",
            &[
                ("id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("api_revision", self.api_revision.clone()),
                ("contract_version", self.contract_version.clone()),
                ("release", self.release.clone()),
                ("capability", self.capability_digest.as_str().to_owned()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        if self.provider_digest != expected {
            return Err(AwsEntityResolutionError::ProviderDrift);
        }
        Ok(())
    }
}

impl Default for AwsEntityResolutionProviderDefinition {
    fn default() -> Self {
        let operations = vec![
            AwsEntityResolutionOperation::ListIdNamespaces,
            AwsEntityResolutionOperation::GetIdNamespace,
            AwsEntityResolutionOperation::GetMatchingWorkflow,
            AwsEntityResolutionOperation::GetSchemaMapping,
            AwsEntityResolutionOperation::GetMatchId,
        ];
        let provider_id = PROVIDER_ID.to_owned();
        let release = PLUGIN_VERSION.to_owned();
        let capability_digest = Digest::from_parts(
            "aws-entity-resolution-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-entity-resolution-provider/v1",
            &[
                ("id", provider_id.clone()),
                ("revision", PROVIDER_REVISION.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            provider_id,
            provider_revision: PROVIDER_REVISION,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            operations,
            allowed_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fixture,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
            connected_evidence: false,
            native_evidence: false,
            first_party_evidence: false,
            provider_receipt: false,
        }
    }
}

pub struct AwsEntityResolutionProvider<T: AwsEntityResolutionTransport> {
    transport: T,
    definition: AwsEntityResolutionProviderDefinition,
}

impl<T: AwsEntityResolutionTransport> fmt::Debug for AwsEntityResolutionProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEntityResolutionProvider")
            .field("provenance", &self.transport.provenance())
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: AwsEntityResolutionTransport> AwsEntityResolutionProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = AwsEntityResolutionProviderDefinition::default();
        Self::with_definition(transport, definition)
    }

    pub fn with_definition(
        transport: T,
        definition: AwsEntityResolutionProviderDefinition,
    ) -> Result<Self> {
        definition.validate()?;
        if !definition
            .allowed_provenance
            .contains(&transport.provenance())
        {
            return Err(AwsEntityResolutionError::ProviderDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsEntityResolutionProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_id_namespaces(
        &mut self,
        request: &ListIdNamespacesRequest,
    ) -> std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError> {
        self.transport.list_id_namespaces(request)
    }

    pub fn get_id_namespace(
        &mut self,
        request: &GetIdNamespaceRequest,
    ) -> std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError> {
        self.transport.get_id_namespace(request)
    }

    pub fn get_matching_workflow(
        &mut self,
        request: &GetMatchingWorkflowRequest,
    ) -> std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError> {
        self.transport.get_matching_workflow(request)
    }

    pub fn get_schema_mapping(
        &mut self,
        request: &GetSchemaMappingRequest,
    ) -> std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError> {
        self.transport.get_schema_mapping(request)
    }

    pub fn get_match_id(
        &mut self,
        request: &GetMatchIdRequest,
    ) -> std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError> {
        self.transport.get_match_id(request)
    }
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    list_responses:
        VecDeque<std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError>>,
    namespace_responses:
        VecDeque<std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError>>,
    workflow_responses:
        VecDeque<std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError>>,
    schema_responses:
        VecDeque<std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError>>,
    match_responses:
        VecDeque<std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError>>,
}

impl RecordingTransport {
    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_namespace_response(
        &mut self,
        response: std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError>,
    ) {
        self.namespace_responses.push_back(response);
    }

    pub fn push_workflow_response(
        &mut self,
        response: std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError>,
    ) {
        self.workflow_responses.push_back(response);
    }

    pub fn push_schema_response(
        &mut self,
        response: std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError>,
    ) {
        self.schema_responses.push_back(response);
    }

    pub fn push_match_response(
        &mut self,
        response: std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError>,
    ) {
        self.match_responses.push_back(response);
    }
}

impl AwsEntityResolutionTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_id_namespaces(
        &mut self,
        _request: &ListIdNamespacesRequest,
    ) -> std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError> {
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsEntityResolutionTransportError::InvalidResponse))
    }

    fn get_id_namespace(
        &mut self,
        _request: &GetIdNamespaceRequest,
    ) -> std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError> {
        self.namespace_responses
            .pop_front()
            .unwrap_or(Err(AwsEntityResolutionTransportError::InvalidResponse))
    }

    fn get_matching_workflow(
        &mut self,
        _request: &GetMatchingWorkflowRequest,
    ) -> std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError> {
        self.workflow_responses
            .pop_front()
            .unwrap_or(Err(AwsEntityResolutionTransportError::InvalidResponse))
    }

    fn get_schema_mapping(
        &mut self,
        _request: &GetSchemaMappingRequest,
    ) -> std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError> {
        self.schema_responses
            .pop_front()
            .unwrap_or(Err(AwsEntityResolutionTransportError::InvalidResponse))
    }

    fn get_match_id(
        &mut self,
        _request: &GetMatchIdRequest,
    ) -> std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError> {
        self.match_responses
            .pop_front()
            .unwrap_or(Err(AwsEntityResolutionTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    namespace: IdNamespaceMetadata,
    workflow: MatchingWorkflowMetadata,
    schema: SchemaMappingMetadata,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsEntityResolutionScope) -> Result<Self> {
        scope.validate()?;
        let attributes = vec![
            crate::model::SchemaAttributeMetadata::from_field(
                "record_key",
                crate::model::SchemaAttributeType::UniqueId,
                true,
                true,
            )?,
            crate::model::SchemaAttributeMetadata::from_field(
                "email",
                crate::model::SchemaAttributeType::EmailAddress,
                false,
                true,
            )?,
        ];
        let schema = SchemaMappingMetadata::new(
            scope.schema_mapping().name().as_str(),
            None::<&str>,
            &attributes,
            true,
            scope.source_record_fingerprint().apply_normalization,
            Some(1_700_000_000),
            Some(1_700_000_100),
        )?;
        let namespace = IdNamespaceMetadata::new(
            scope.id_namespace().name().as_str(),
            None::<&str>,
            crate::model::IdNamespaceType::Source,
            Some("bounded fixture namespace"),
            &["SOURCE"],
            Some(1_700_000_000),
            Some(1_700_000_100),
        )?;
        let workflow = MatchingWorkflowMetadata::new(
            scope.matching_workflow().name().as_str(),
            None::<&str>,
            crate::model::MatchingType::RuleBased,
            schema.metadata_digest.clone(),
            Some(namespace.metadata_digest.clone()),
            1,
            scope.source_record_fingerprint().apply_normalization,
            1,
            Some(1_700_000_000),
            Some(1_700_000_100),
        )?;
        Ok(Self {
            scope_digest: scope.digest(),
            namespace,
            workflow,
            schema,
        })
    }

    fn check_scope(
        &self,
        scope_digest: &Digest,
    ) -> std::result::Result<(), AwsEntityResolutionTransportError> {
        if scope_digest == &self.scope_digest {
            Ok(())
        } else {
            Err(AwsEntityResolutionTransportError::InvalidResponse)
        }
    }
}

impl AwsEntityResolutionTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_id_namespaces(
        &mut self,
        request: &ListIdNamespacesRequest,
    ) -> std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError> {
        self.check_scope(request.scope_digest())?;
        ListIdNamespacesResponse::new(
            request,
            vec![self.namespace.clone()],
            None,
            512,
            self.provenance(),
        )
        .map_err(|_| AwsEntityResolutionTransportError::InvalidResponse)
    }

    fn get_id_namespace(
        &mut self,
        request: &GetIdNamespaceRequest,
    ) -> std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError> {
        self.check_scope(request.scope_digest())?;
        IdNamespaceResponse::new(request, self.namespace.clone(), 384, self.provenance())
            .map_err(|_| AwsEntityResolutionTransportError::InvalidResponse)
    }

    fn get_matching_workflow(
        &mut self,
        request: &GetMatchingWorkflowRequest,
    ) -> std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError> {
        self.check_scope(request.scope_digest())?;
        MatchingWorkflowResponse::new(request, self.workflow.clone(), 384, self.provenance())
            .map_err(|_| AwsEntityResolutionTransportError::InvalidResponse)
    }

    fn get_schema_mapping(
        &mut self,
        request: &GetSchemaMappingRequest,
    ) -> std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError> {
        self.check_scope(request.scope_digest())?;
        SchemaMappingResponse::new(request, self.schema.clone(), 512, self.provenance())
            .map_err(|_| AwsEntityResolutionTransportError::InvalidResponse)
    }

    fn get_match_id(
        &mut self,
        request: &GetMatchIdRequest,
    ) -> std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError> {
        self.check_scope(request.scope_digest())?;
        GetMatchIdResponse::matched(
            request,
            request
                .source_record_fingerprint()
                .fingerprint_digest()
                .as_str(),
            "rule-1",
            self.provenance(),
        )
        .map_err(|_| AwsEntityResolutionTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsEntityResolutionScope) -> Result<Self> {
        Ok(Self {
            fixture: FixtureTransport::for_scope(scope)?,
        })
    }
}

impl AwsEntityResolutionTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_id_namespaces(
        &mut self,
        request: &ListIdNamespacesRequest,
    ) -> std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError> {
        self.fixture
            .list_id_namespaces(request)
            .map(|response| response.with_provenance(self.provenance()))
    }

    fn get_id_namespace(
        &mut self,
        request: &GetIdNamespaceRequest,
    ) -> std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError> {
        self.fixture
            .get_id_namespace(request)
            .map(|response| response.with_provenance(self.provenance()))
    }

    fn get_matching_workflow(
        &mut self,
        request: &GetMatchingWorkflowRequest,
    ) -> std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError> {
        self.fixture
            .get_matching_workflow(request)
            .map(|response| response.with_provenance(self.provenance()))
    }

    fn get_schema_mapping(
        &mut self,
        request: &GetSchemaMappingRequest,
    ) -> std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError> {
        self.fixture
            .get_schema_mapping(request)
            .map(|response| response.with_provenance(self.provenance()))
    }

    fn get_match_id(
        &mut self,
        request: &GetMatchIdRequest,
    ) -> std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError> {
        self.fixture
            .get_match_id(request)
            .map(|response| response.with_provenance(self.provenance()))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsEntityResolutionTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_id_namespaces(
        &mut self,
        _request: &ListIdNamespacesRequest,
    ) -> std::result::Result<ListIdNamespacesResponse, AwsEntityResolutionTransportError> {
        Err(AwsEntityResolutionTransportError::BlockedEnv)
    }

    fn get_id_namespace(
        &mut self,
        _request: &GetIdNamespaceRequest,
    ) -> std::result::Result<IdNamespaceResponse, AwsEntityResolutionTransportError> {
        Err(AwsEntityResolutionTransportError::BlockedEnv)
    }

    fn get_matching_workflow(
        &mut self,
        _request: &GetMatchingWorkflowRequest,
    ) -> std::result::Result<MatchingWorkflowResponse, AwsEntityResolutionTransportError> {
        Err(AwsEntityResolutionTransportError::BlockedEnv)
    }

    fn get_schema_mapping(
        &mut self,
        _request: &GetSchemaMappingRequest,
    ) -> std::result::Result<SchemaMappingResponse, AwsEntityResolutionTransportError> {
        Err(AwsEntityResolutionTransportError::BlockedEnv)
    }

    fn get_match_id(
        &mut self,
        _request: &GetMatchIdRequest,
    ) -> std::result::Result<GetMatchIdResponse, AwsEntityResolutionTransportError> {
        Err(AwsEntityResolutionTransportError::BlockedEnv)
    }
}

pub const fn layer_one_permissions() -> &'static [&'static str] {
    &LAYER1_PERMISSIONS
}
