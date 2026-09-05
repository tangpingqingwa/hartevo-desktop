//! Provider identity and bounded transport seams for AWS RAM.
//!
//! Layer 1 deliberately has no AWS SDK, SigV4 signer, credential resolver, or
//! native HTTP client. A transport can only return already bounded metadata
//! pages or a redacted transport failure.

use std::{collections::VecDeque, fmt};

use serde_json::Value;
use thiserror::Error;

use crate::{
    AWS_RAM_API_REVISION, AWS_RAM_PROVIDER_ID, AWS_RAM_PROVIDER_VERSION,
    model::{
        AssociationStatus, InvitationMetadata, InvitationStatus, ModelError, OpaquePageToken,
        PermissionMetadata, PrincipalMetadata, RamOperation, RamPageItems, RamReadPage,
        RamReadRequest, ResourceMetadata, ResourceRegionScope, ResourceShareMetadata,
        ResourceShareStatus, ResourceType, Revision, ShareName, TransportError,
        TransportProvenance,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS RAM provider model is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS RAM provider revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsRamProviderIdentity {
    pub provider_id: String,
    pub version: String,
    pub api_revision: String,
    pub provider_digest: crate::model::Digest,
    pub api_digest: crate::model::Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsRamProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_digest = crate::model::Digest::from_parts(
            "hartevo-aws-ram-provider/v1",
            &[
                AWS_RAM_PROVIDER_ID.to_owned(),
                AWS_RAM_PROVIDER_VERSION.to_owned(),
                AWS_RAM_API_REVISION.to_owned(),
            ],
        );
        let api_digest = crate::model::Digest::from_parts(
            "hartevo-aws-ram-api-allowlist/v1",
            &RamOperation::ALL
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            provider_id: AWS_RAM_PROVIDER_ID.to_owned(),
            version: AWS_RAM_PROVIDER_VERSION.to_owned(),
            api_revision: AWS_RAM_API_REVISION.to_owned(),
            provider_digest,
            api_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }
}

pub type AwsRamProviderDefinition = AwsRamProviderIdentity;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsRamProviderError {
    #[error("AWS RAM provider request is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS RAM provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("AWS RAM provider page binding or digest is invalid")]
    PageBinding,
    #[error("AWS RAM provider revision is incompatible")]
    ProviderRevision,
}

pub trait AwsRamTransport: fmt::Debug + Send {
    fn provenance(&self) -> TransportProvenance;

    fn read(&mut self, request: &RamReadRequest) -> Result<RamReadPage, TransportError>;
}

pub struct AwsRamProvider<T> {
    transport: T,
    identity: AwsRamProviderIdentity,
}

impl<T> fmt::Debug for AwsRamProvider<T>
where
    T: AwsRamTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRamProvider")
            .field("provider_id", &self.identity.provider_id)
            .field("version", &self.identity.version)
            .field("api_revision", &self.identity.api_revision)
            .field("provider_digest", &self.identity.provider_digest)
            .field("api_digest", &self.identity.api_digest)
            .field("provenance", &self.identity.provenance)
            .field("connected", &self.identity.connected)
            .field("native", &self.identity.native)
            .field("first_party", &self.identity.first_party)
            .finish_non_exhaustive()
    }
}

impl<T> AwsRamProvider<T>
where
    T: AwsRamTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AwsRamProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &AwsRamProviderIdentity {
        &self.identity
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self, request: &RamReadRequest) -> Result<RamReadPage, AwsRamProviderError> {
        request.validate()?;
        let page = self.transport.read(request)?;
        page.validate_for(request, &self.identity.api_revision)
            .map_err(|_| AwsRamProviderError::PageBinding)?;
        Ok(page)
    }

    /// Parses only the documented metadata fields from an already bounded
    /// response. Raw provider payloads are not returned or retained.
    pub fn parse_json_page(
        request: &RamReadRequest,
        status_code: u16,
        body: &[u8],
        association_revision: Revision,
    ) -> Result<RamReadPage, AwsRamProviderError> {
        if status_code != 200 {
            return Err(AwsRamProviderError::Transport(transport_error_for_status(
                status_code,
            )));
        }
        if body.is_empty() || body.len() > crate::model::MAX_RESPONSE_BYTES {
            return Err(AwsRamProviderError::Model(ModelError::BoundExceeded {
                field: "provider response bytes",
            }));
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsRamProviderError::Transport(TransportError::MalformedResponse))?;
        let next_token = value
            .get("nextToken")
            .or_else(|| value.get("NextToken"))
            .and_then(Value::as_str)
            .map(OpaquePageToken::new)
            .transpose()?;
        let items = match request.operation {
            RamOperation::GetResourceShares => {
                RamPageItems::ResourceShares(parse_resource_shares(&value)?)
            }
            RamOperation::ListResources => RamPageItems::Resources(parse_resources(&value)?),
            RamOperation::ListPrincipals => RamPageItems::Principals(parse_principals(&value)?),
            RamOperation::ListResourceSharePermissions => {
                RamPageItems::Permissions(parse_permissions(&value)?)
            }
            RamOperation::GetResourceShareInvitations => {
                RamPageItems::Invitations(parse_invitations(&value)?)
            }
        };
        RamReadPage::new(
            request,
            items,
            next_token,
            body.len(),
            association_revision,
            AWS_RAM_API_REVISION,
        )
        .map_err(AwsRamProviderError::Model)
    }
}

fn transport_error_for_status(status_code: u16) -> TransportError {
    match status_code {
        400 | 404 => TransportError::InvalidRequest,
        401 | 403 => TransportError::AccessLoss,
        429 => TransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => TransportError::Unavailable,
        _ => TransportError::ProviderUnknown,
    }
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, AwsRamProviderError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        ))
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn timestamp(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or_default()
}

fn bool_value(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn parse_resource_share_status(value: &str) -> Result<ResourceShareStatus, AwsRamProviderError> {
    match value {
        "PENDING" => Ok(ResourceShareStatus::Pending),
        "ACTIVE" => Ok(ResourceShareStatus::Active),
        "FAILED" => Ok(ResourceShareStatus::Failed),
        "DELETING" => Ok(ResourceShareStatus::Deleting),
        "DELETED" => Ok(ResourceShareStatus::Deleted),
        _ => Err(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        )),
    }
}

fn parse_region_scope(value: &str) -> Result<ResourceRegionScope, AwsRamProviderError> {
    match value {
        "ALL" => Ok(ResourceRegionScope::All),
        "REGIONAL" => Ok(ResourceRegionScope::Regional),
        "GLOBAL" => Ok(ResourceRegionScope::Global),
        _ => Err(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        )),
    }
}

fn parse_association_status(value: &str) -> Result<AssociationStatus, AwsRamProviderError> {
    match value {
        "ASSOCIATED" => Ok(AssociationStatus::Associated),
        "DISASSOCIATED" => Ok(AssociationStatus::Disassociated),
        _ => Err(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        )),
    }
}

fn parse_invitation_status(value: &str) -> Result<InvitationStatus, AwsRamProviderError> {
    match value {
        "PENDING" => Ok(InvitationStatus::Pending),
        "ACCEPTED" => Ok(InvitationStatus::Accepted),
        "DECLINED" => Ok(InvitationStatus::Declined),
        _ => Err(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        )),
    }
}

fn parse_resource_shares(value: &Value) -> Result<Vec<ResourceShareMetadata>, AwsRamProviderError> {
    value
        .get("resourceShares")
        .and_then(Value::as_array)
        .ok_or(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        ))?
        .iter()
        .map(|item| {
            let configuration = item
                .get("resourceShareConfiguration")
                .unwrap_or(&Value::Null);
            Ok(ResourceShareMetadata {
                resource_share_arn: crate::model::ResourceShareArn::new(required_string(
                    item,
                    "resourceShareArn",
                )?)?,
                name: ShareName::new(required_string(item, "name")?)?,
                owning_account: crate::model::AwsAccountId::new(required_string(
                    item,
                    "owningAccountId",
                )?)?,
                status: parse_resource_share_status(required_string(item, "status")?)?,
                allow_external_principals: bool_value(item, "allowExternalPrincipals"),
                feature_set: optional_string(item, "featureSet"),
                creation_time: timestamp(item, "creationTime"),
                last_updated_time: timestamp(item, "lastUpdatedTime"),
                retain_sharing_on_account_leave_organization: bool_value(
                    configuration,
                    "retainSharingOnAccountLeaveOrganization",
                ),
                association_revision: Revision::new(1)?,
            })
        })
        .collect()
}

fn parse_resources(value: &Value) -> Result<Vec<ResourceMetadata>, AwsRamProviderError> {
    value
        .get("resources")
        .and_then(Value::as_array)
        .ok_or(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        ))?
        .iter()
        .map(|item| {
            Ok(ResourceMetadata {
                arn: crate::model::ResourceArn::new(required_string(item, "arn")?)?,
                resource_share_arn: crate::model::ResourceShareArn::new(required_string(
                    item,
                    "resourceShareArn",
                )?)?,
                resource_type: ResourceType::new(required_string(item, "type")?)?,
                resource_region_scope: parse_region_scope(required_string(
                    item,
                    "resourceRegionScope",
                )?)?,
                status: parse_association_status(required_string(item, "status")?)?,
                resource_group_arn: optional_string(item, "resourceGroupArn")
                    .map(crate::model::ResourceArn::new)
                    .transpose()?,
                creation_time: timestamp(item, "creationTime"),
                last_updated_time: timestamp(item, "lastUpdatedTime"),
                association_revision: Revision::new(1)?,
            })
        })
        .collect()
}

fn parse_principals(value: &Value) -> Result<Vec<PrincipalMetadata>, AwsRamProviderError> {
    value
        .get("principals")
        .and_then(Value::as_array)
        .ok_or(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        ))?
        .iter()
        .map(|item| {
            Ok(PrincipalMetadata {
                id: crate::model::PrincipalId::new(required_string(item, "id")?)?,
                resource_share_arn: crate::model::ResourceShareArn::new(required_string(
                    item,
                    "resourceShareArn",
                )?)?,
                external: bool_value(item, "external"),
                creation_time: timestamp(item, "creationTime"),
                last_updated_time: timestamp(item, "lastUpdatedTime"),
                association_revision: Revision::new(1)?,
            })
        })
        .collect()
}

fn parse_permissions(value: &Value) -> Result<Vec<PermissionMetadata>, AwsRamProviderError> {
    value
        .get("permissions")
        .and_then(Value::as_array)
        .ok_or(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        ))?
        .iter()
        .map(|item| {
            let version = item
                .get("version")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(AwsRamProviderError::Transport(
                    TransportError::MalformedResponse,
                ))?;
            Ok(PermissionMetadata {
                permission_arn: crate::model::PermissionArn::new(required_string(item, "arn")?)?,
                version,
                default_version: bool_value(item, "defaultVersion"),
                resource_type: ResourceType::new(required_string(item, "resourceType")?)?,
                customer_managed: optional_string(item, "permissionType").as_deref()
                    == Some("CUSTOMER_MANAGED"),
                association_revision: Revision::new(1)?,
            })
        })
        .collect()
}

fn parse_invitations(value: &Value) -> Result<Vec<InvitationMetadata>, AwsRamProviderError> {
    value
        .get("resourceShareInvitations")
        .and_then(Value::as_array)
        .ok_or(AwsRamProviderError::Transport(
            TransportError::MalformedResponse,
        ))?
        .iter()
        .map(|item| {
            Ok(InvitationMetadata {
                invitation_arn: crate::model::InvitationArn::new(required_string(
                    item,
                    "resourceShareInvitationArn",
                )?)?,
                resource_share_arn: crate::model::ResourceShareArn::new(required_string(
                    item,
                    "resourceShareArn",
                )?)?,
                sender_account: crate::model::AwsAccountId::new(required_string(
                    item,
                    "senderAccountId",
                )?)?,
                receiver_account: crate::model::AwsAccountId::new(required_string(
                    item,
                    "receiverAccountId",
                )?)?,
                status: parse_invitation_status(required_string(item, "status")?)?,
                creation_time: timestamp(item, "invitationTimestamp"),
                expiration_time: item.get("expirationTime").and_then(Value::as_i64),
                association_revision: Revision::new(1)?,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportCall {
    pub operation: RamOperation,
    pub request_digest: crate::model::Digest,
    pub filter_digest: crate::model::Digest,
    pub cursor_digest: Option<crate::model::Digest>,
    pub path_digest: crate::model::Digest,
    pub redacted: bool,
}

#[derive(Clone, Debug)]
struct QueuedRamTransport {
    provenance: TransportProvenance,
    responses: VecDeque<Result<RamReadPage, TransportError>>,
    calls: Vec<TransportCall>,
}

impl QueuedRamTransport {
    fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    fn push_response(&mut self, response: Result<RamReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn read(&mut self, request: &RamReadRequest) -> Result<RamReadPage, TransportError> {
        self.calls.push(TransportCall {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            filter_digest: request.filter.digest(),
            cursor_digest: request.cursor_digest(),
            path_digest: crate::model::Digest::from_parts(
                "aws-ram-redacted-request-path/v1",
                &[
                    request.operation.as_str().to_owned(),
                    request.scope.scope_digest.as_str().to_owned(),
                    request.filter.digest().as_str().to_owned(),
                    request
                        .cursor_digest()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ],
            ),
            redacted: true,
        });
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAwsRamTransport {
    inner: QueuedRamTransport,
}

impl Default for FixtureAwsRamTransport {
    fn default() -> Self {
        Self::fixture()
    }
}

impl FixtureAwsRamTransport {
    pub fn fixture() -> Self {
        Self {
            inner: QueuedRamTransport::new(TransportProvenance::Fixture),
        }
    }

    pub fn push_response(&mut self, response: Result<RamReadPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl AwsRamTransport for FixtureAwsRamTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn read(&mut self, request: &RamReadRequest) -> Result<RamReadPage, TransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAwsRamTransport {
    inner: QueuedRamTransport,
}

impl Default for RecordingAwsRamTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingAwsRamTransport {
    pub fn new() -> Self {
        Self {
            inner: QueuedRamTransport::new(TransportProvenance::Recording),
        }
    }

    pub fn push_response(&mut self, response: Result<RamReadPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl AwsRamTransport for RecordingAwsRamTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn read(&mut self, request: &RamReadRequest) -> Result<RamReadPage, TransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAwsRamTransport {
    inner: QueuedRamTransport,
}

impl Default for LoopbackAwsRamTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackAwsRamTransport {
    pub fn new() -> Self {
        Self {
            inner: QueuedRamTransport::new(TransportProvenance::Loopback),
        }
    }

    pub fn push_response(&mut self, response: Result<RamReadPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl AwsRamTransport for LoopbackAwsRamTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn read(&mut self, request: &RamReadRequest) -> Result<RamReadPage, TransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsRamTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(&mut self, _request: &RamReadRequest) -> Result<RamReadPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }
}

pub type FakeAwsRamTransport = FixtureAwsRamTransport;
