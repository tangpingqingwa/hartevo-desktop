use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{AwsConnectContactResultError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_ATTRIBUTES, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES,
};

pub const MAX_WINDOW_SECONDS: i64 = 31 * 24 * 60 * 60;
pub const MAX_CONTACT_ID_BYTES: usize = 256;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsConnectContactResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsConnectContactResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

macro_rules! redacted_id {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsConnectContactResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-connect-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsConnectContactResultError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format!("{}:{}", $field, &self.digest().as_str()[..16]))
                    .finish()
            }
        }
    };
}

redacted_id!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_id!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
redacted_id!(ConnectInstanceId, "connect-instance", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_id!(ContactId, "contact", |value: &str| {
    valid_identifier(value, MAX_CONTACT_ID_BYTES)
});
redacted_id!(QueueId, "queue", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_id!(AgentId, "agent", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactChannel {
    Voice,
    Chat,
    Task,
    Email,
    Sms,
}

impl ContactChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Voice => "voice",
            Self::Chat => "chat",
            Self::Task => "task",
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UtcTimeWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl UtcTimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self> {
        let seconds = end.signed_duration_since(start).num_seconds();
        if seconds <= 0 || seconds > MAX_WINDOW_SECONDS {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        Ok(Self { start, end })
    }

    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    pub fn end(&self) -> DateTime<Utc> {
        self.end
    }

    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-time-window-utc/v1",
            &[
                ("start", self.start.to_rfc3339()),
                ("end", self.end.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: String,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsConnectContactResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-mission/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsConnectContactResultError::InvalidScope)
        }
    }
}

impl fmt::Debug for MissionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIdentity")
            .field("id_digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: String,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsConnectContactResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-project/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsConnectContactResultError::InvalidScope)
        }
    }
}

impl fmt::Debug for ProjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentity")
            .field("id_digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: String,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsConnectContactResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-work-product/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsConnectContactResultError::InvalidScope)
        }
    }
}

impl fmt::Debug for WorkProductIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductIdentity")
            .field("id_digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsConnectContactScope {
    account: AwsAccountId,
    region: AwsRegion,
    instance: ConnectInstanceId,
    contact: ContactId,
    queue: QueueId,
    agent: AgentId,
    channel: ContactChannel,
    time_window: UtcTimeWindow,
    project: ProjectIdentity,
    mission: MissionIdentity,
    work_product: WorkProductIdentity,
}

impl AwsConnectContactScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        instance: ConnectInstanceId,
        contact: ContactId,
        queue: QueueId,
        agent: AgentId,
        channel: ContactChannel,
        time_window: UtcTimeWindow,
        project: ProjectIdentity,
        mission: MissionIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            instance,
            contact,
            queue,
            agent,
            channel,
            time_window,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn instance(&self) -> &ConnectInstanceId {
        &self.instance
    }

    pub fn contact(&self) -> &ContactId {
        &self.contact
    }

    pub fn queue(&self) -> &QueueId {
        &self.queue
    }

    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    pub const fn channel(&self) -> ContactChannel {
        self.channel
    }

    pub fn time_window(&self) -> &UtcTimeWindow {
        &self.time_window
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-contact-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("instance", self.instance.digest().as_str().to_owned()),
                ("contact", self.contact.digest().as_str().to_owned()),
                ("queue", self.queue.digest().as_str().to_owned()),
                ("agent", self.agent.digest().as_str().to_owned()),
                ("channel", self.channel.as_str().to_owned()),
                ("time_window", self.time_window.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.instance.validate()?;
        self.contact.validate()?;
        self.queue.validate()?;
        self.agent.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsConnectContactScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsConnectContactScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("instance", &self.instance)
            .field("contact", &self.contact)
            .field("queue", &self.queue)
            .field("agent", &self.agent)
            .field("channel", &self.channel)
            .field("time_window", &self.time_window)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeProjection {
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub instance_digest: Digest,
    pub contact_digest: Digest,
    pub queue_digest: Digest,
    pub agent_digest: Digest,
    pub channel: ContactChannel,
    pub time_window: UtcTimeWindow,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
}

pub(crate) fn mission_projection(mission: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: mission.digest(),
        revision: mission.revision,
    }
}

pub(crate) fn project_projection(project: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: project.digest(),
        revision: project.revision,
    }
}

pub(crate) fn work_product_projection(work_product: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: work_product.digest(),
        revision: work_product.revision,
    }
}

pub(crate) fn scope_projection(scope: &AwsConnectContactScope) -> ScopeProjection {
    ScopeProjection {
        scope_digest: scope.digest(),
        account_digest: scope.account.digest(),
        region_digest: scope.region.digest(),
        instance_digest: scope.instance.digest(),
        contact_digest: scope.contact.digest(),
        queue_digest: scope.queue.digest(),
        agent_digest: scope.agent.digest(),
        channel: scope.channel,
        time_window: scope.time_window.clone(),
        project: project_projection(&scope.project),
        mission: mission_projection(&scope.mission),
        work_product: work_product_projection(&scope.work_product),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactState {
    Initiated,
    Connected,
    Ended,
    Missed,
    Transferred,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiationMethod {
    Inbound,
    Outbound,
    Transfer,
    Callback,
    Api,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReasonClass {
    CustomerDisconnect,
    AgentDisconnect,
    ThirdPartyTransfer,
    ContactFlowEnd,
    SystemError,
    Other,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContactLifecycle {
    initiation_timestamp: DateTime<Utc>,
    connected_timestamp: Option<DateTime<Utc>>,
    last_update_timestamp: DateTime<Utc>,
    disconnect_timestamp: Option<DateTime<Utc>>,
    state: ContactState,
    initiation_method: InitiationMethod,
    disconnect_reason: Option<DisconnectReasonClass>,
}

impl ContactLifecycle {
    pub fn new(
        initiation_timestamp: DateTime<Utc>,
        connected_timestamp: Option<DateTime<Utc>>,
        last_update_timestamp: DateTime<Utc>,
        disconnect_timestamp: Option<DateTime<Utc>>,
        state: ContactState,
        initiation_method: InitiationMethod,
        disconnect_reason: Option<DisconnectReasonClass>,
    ) -> Result<Self> {
        if connected_timestamp.is_some_and(|value| value < initiation_timestamp)
            || last_update_timestamp < initiation_timestamp
            || disconnect_timestamp.is_some_and(|value| value < initiation_timestamp)
            || disconnect_reason.is_some() != disconnect_timestamp.is_some()
        {
            return Err(AwsConnectContactResultError::InvalidScope);
        }
        Ok(Self {
            initiation_timestamp,
            connected_timestamp,
            last_update_timestamp,
            disconnect_timestamp,
            state,
            initiation_method,
            disconnect_reason,
        })
    }

    pub fn initiation_timestamp(&self) -> DateTime<Utc> {
        self.initiation_timestamp
    }

    pub fn connected_timestamp(&self) -> Option<DateTime<Utc>> {
        self.connected_timestamp
    }

    pub fn last_update_timestamp(&self) -> DateTime<Utc> {
        self.last_update_timestamp
    }

    pub fn disconnect_timestamp(&self) -> Option<DateTime<Utc>> {
        self.disconnect_timestamp
    }

    pub const fn state(&self) -> ContactState {
        self.state
    }

    pub const fn initiation_method(&self) -> InitiationMethod {
        self.initiation_method
    }

    pub const fn disconnect_reason(&self) -> Option<DisconnectReasonClass> {
        self.disconnect_reason
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-contact-lifecycle/v1",
            &[
                ("initiation", self.initiation_timestamp.to_rfc3339()),
                (
                    "connected",
                    self.connected_timestamp
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("last_update", self.last_update_timestamp.to_rfc3339()),
                (
                    "disconnect",
                    self.disconnect_timestamp
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("state", format!("{:?}", self.state)),
                ("initiation_method", format!("{:?}", self.initiation_method)),
                (
                    "disconnect_reason",
                    self.disconnect_reason
                        .map_or_else(String::new, |value| format!("{value:?}")),
                ),
            ],
        )
    }
}

impl fmt::Debug for ContactLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContactLifecycle")
            .field("digest", &self.digest())
            .field("initiation_timestamp", &self.initiation_timestamp)
            .field("connected_timestamp", &self.connected_timestamp)
            .field("last_update_timestamp", &self.last_update_timestamp)
            .field("disconnect_timestamp", &self.disconnect_timestamp)
            .field("state", &self.state)
            .field("initiation_method", &self.initiation_method)
            .field("disconnect_reason", &self.disconnect_reason)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContactRecord {
    contact: ContactId,
    instance: ConnectInstanceId,
    queue: QueueId,
    agent: AgentId,
    channel: ContactChannel,
    lifecycle: ContactLifecycle,
}

impl ContactRecord {
    pub fn new(
        contact: ContactId,
        instance: ConnectInstanceId,
        queue: QueueId,
        agent: AgentId,
        channel: ContactChannel,
        lifecycle: ContactLifecycle,
    ) -> Result<Self> {
        let record = Self {
            contact,
            instance,
            queue,
            agent,
            channel,
            lifecycle,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn for_scope(scope: &AwsConnectContactScope, lifecycle: ContactLifecycle) -> Result<Self> {
        Self::new(
            scope.contact.clone(),
            scope.instance.clone(),
            scope.queue.clone(),
            scope.agent.clone(),
            scope.channel,
            lifecycle,
        )
    }

    pub fn contact(&self) -> &ContactId {
        &self.contact
    }

    pub fn instance(&self) -> &ConnectInstanceId {
        &self.instance
    }

    pub fn queue(&self) -> &QueueId {
        &self.queue
    }

    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    pub const fn channel(&self) -> ContactChannel {
        self.channel
    }

    pub fn lifecycle(&self) -> &ContactLifecycle {
        &self.lifecycle
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-contact-record/v1",
            &[
                ("contact", self.contact.digest().as_str().to_owned()),
                ("instance", self.instance.digest().as_str().to_owned()),
                ("queue", self.queue.digest().as_str().to_owned()),
                ("agent", self.agent.digest().as_str().to_owned()),
                ("channel", self.channel.as_str().to_owned()),
                ("lifecycle", self.lifecycle.digest().as_str().to_owned()),
            ],
        )
    }

    pub fn matches_scope(&self, scope: &AwsConnectContactScope) -> bool {
        self.contact == scope.contact
            && self.instance == scope.instance
            && self.queue == scope.queue
            && self.agent == scope.agent
            && self.channel == scope.channel
            && scope
                .time_window
                .contains(self.lifecycle.initiation_timestamp)
    }

    pub fn projection(&self) -> ContactProjection {
        ContactProjection {
            contact_digest: self.contact.digest(),
            instance_digest: self.instance.digest(),
            queue_digest: self.queue.digest(),
            agent_digest: self.agent.digest(),
            channel: self.channel,
            lifecycle: ContactLifecycleProjection {
                initiation_timestamp: self.lifecycle.initiation_timestamp,
                connected_timestamp: self.lifecycle.connected_timestamp,
                last_update_timestamp: self.lifecycle.last_update_timestamp,
                disconnect_timestamp: self.lifecycle.disconnect_timestamp,
                state: self.lifecycle.state,
                initiation_method: self.lifecycle.initiation_method,
                disconnect_reason: self.lifecycle.disconnect_reason,
            },
            contact_record_digest: self.digest(),
        }
    }

    fn validate(&self) -> Result<()> {
        self.contact.validate()?;
        self.instance.validate()?;
        self.queue.validate()?;
        self.agent.validate()
    }

    pub(crate) fn validate_against(&self, scope: &AwsConnectContactScope) -> Result<()> {
        if !self.matches_scope(scope) {
            return Err(AwsConnectContactResultError::ScopeMismatch);
        }
        self.validate()
    }
}

impl fmt::Debug for ContactRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContactRecord")
            .field("digest", &self.digest())
            .field("contact", &self.contact)
            .field("instance", &self.instance)
            .field("queue", &self.queue)
            .field("agent", &self.agent)
            .field("channel", &self.channel)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactLifecycleProjection {
    pub initiation_timestamp: DateTime<Utc>,
    pub connected_timestamp: Option<DateTime<Utc>>,
    pub last_update_timestamp: DateTime<Utc>,
    pub disconnect_timestamp: Option<DateTime<Utc>>,
    pub state: ContactState,
    pub initiation_method: InitiationMethod,
    pub disconnect_reason: Option<DisconnectReasonClass>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactProjection {
    pub contact_digest: Digest,
    pub instance_digest: Digest,
    pub queue_digest: Digest,
    pub agent_digest: Digest,
    pub channel: ContactChannel,
    pub lifecycle: ContactLifecycleProjection,
    pub contact_record_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeKeyClass {
    CustomerReference,
    CaseReference,
    Language,
    Intent,
    OutcomeCode,
    CampaignReference,
}

impl AttributeKeyClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CustomerReference => "customer_reference",
            Self::CaseReference => "case_reference",
            Self::Language => "language",
            Self::Intent => "intent",
            Self::OutcomeCode => "outcome_code",
            Self::CampaignReference => "campaign_reference",
        }
    }

    pub fn from_wire_key(key: &str) -> Result<Self> {
        match key {
            "customer_reference" => Ok(Self::CustomerReference),
            "case_reference" => Ok(Self::CaseReference),
            "language" => Ok(Self::Language),
            "intent" => Ok(Self::Intent),
            "outcome_code" => Ok(Self::OutcomeCode),
            "campaign_reference" => Ok(Self::CampaignReference),
            _ => Err(AwsConnectContactResultError::AttributeNotAllowlisted),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AttributeValueInput {
    key_class: AttributeKeyClass,
    value_digest: Digest,
}

impl AttributeValueInput {
    pub fn from_raw(key_class: AttributeKeyClass, value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        if !valid_text(value, 4096, true) {
            return Err(AwsConnectContactResultError::InvalidText {
                field: "contact-attribute-value",
            });
        }
        Ok(Self {
            key_class,
            value_digest: Digest::from_parts(
                "aws-connect-contact-attribute-value/v1",
                &[
                    ("key_class", key_class.as_str().to_owned()),
                    ("value", value.to_owned()),
                ],
            ),
        })
    }

    pub fn from_digest(key_class: AttributeKeyClass, value_digest: Digest) -> Result<Self> {
        value_digest.validate()?;
        Ok(Self {
            key_class,
            value_digest,
        })
    }

    pub const fn key_class(&self) -> AttributeKeyClass {
        self.key_class
    }

    pub fn value_digest(&self) -> &Digest {
        &self.value_digest
    }
}

impl fmt::Debug for AttributeValueInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttributeValueInput")
            .field("key_class", &self.key_class)
            .field("value_digest", &self.value_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributeEvidence {
    pub key_class: AttributeKeyClass,
    pub value_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributeEvidenceProjection {
    pub attributes: Vec<AttributeEvidence>,
    pub evidence_digest: Digest,
}

impl AttributeEvidenceProjection {
    pub fn from_inputs(inputs: &[AttributeValueInput]) -> Result<Self> {
        if inputs.len() > MAX_ATTRIBUTES {
            return Err(AwsConnectContactResultError::PartialEvidence);
        }
        let mut attributes = inputs
            .iter()
            .map(|input| AttributeEvidence {
                key_class: input.key_class,
                value_digest: input.value_digest.clone(),
            })
            .collect::<Vec<_>>();
        attributes.sort_by_key(|value| value.key_class);
        if attributes
            .windows(2)
            .any(|values| values[0].key_class == values[1].key_class)
        {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        let evidence_digest = Digest::from_parts(
            "aws-connect-contact-attributes-evidence/v1",
            &[(
                "attributes",
                serde_json::to_string(&attributes).expect("attribute evidence serializes"),
            )],
        );
        Ok(Self {
            attributes,
            evidence_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4,
}

/// Opaque SigV4 reference. The caller-supplied handle is hashed and dropped;
/// it is never serializable, displayable, or present in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
}

impl SecretReference {
    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsConnectContactScope,
        revision: u64,
    ) -> Result<Self> {
        let handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            return Err(AwsConnectContactResultError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "aws-connect-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4".to_owned()),
                ("handle", handle),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            kind: SecretKind::Sigv4,
            reference_digest,
            scope_digest,
            revision,
        })
    }

    pub fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn validate(&self, scope: &AwsConnectContactScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4)
            || self.revision == 0
            || self.scope_digest != scope.digest()
        {
            return Err(AwsConnectContactResultError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsConnectContactResultError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id_digest: Digest,
    revision: u64,
    permissions: BTreeSet<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) {
            return Err(AwsConnectContactResultError::InvalidConsent);
        }
        let consent = Self {
            id_digest: Digest::from_text(id),
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-consent/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.expires_at <= DateTime::<Utc>::MIN_UTC
        {
            Err(AwsConnectContactResultError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("id_digest", &self.id_digest)
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactFilterField {
    ContactId,
    InstanceId,
    QueueId,
    AgentId,
    Channel,
    State,
    InitiationMethod,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum ContactFilter {
    ContactId(ContactId),
    InstanceId(ConnectInstanceId),
    QueueId(QueueId),
    AgentId(AgentId),
    Channel(ContactChannel),
    State(ContactState),
    InitiationMethod(InitiationMethod),
}

impl ContactFilter {
    pub const fn field(&self) -> ContactFilterField {
        match self {
            Self::ContactId(_) => ContactFilterField::ContactId,
            Self::InstanceId(_) => ContactFilterField::InstanceId,
            Self::QueueId(_) => ContactFilterField::QueueId,
            Self::AgentId(_) => ContactFilterField::AgentId,
            Self::Channel(_) => ContactFilterField::Channel,
            Self::State(_) => ContactFilterField::State,
            Self::InitiationMethod(_) => ContactFilterField::InitiationMethod,
        }
    }

    pub fn digest(&self) -> Digest {
        let value = match self {
            Self::ContactId(value) => value.digest(),
            Self::InstanceId(value) => value.digest(),
            Self::QueueId(value) => value.digest(),
            Self::AgentId(value) => value.digest(),
            Self::Channel(value) => Digest::from_text(value.as_str()),
            Self::State(value) => Digest::from_text(format!("{value:?}")),
            Self::InitiationMethod(value) => Digest::from_text(format!("{value:?}")),
        };
        Digest::from_parts(
            "aws-connect-contact-filter/v1",
            &[
                ("field", format!("{:?}", self.field())),
                ("value", value.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for ContactFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContactFilter")
            .field("field", &self.field())
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactSortField {
    InitiationTimestamp,
    LastUpdateTimestamp,
    DisconnectTimestamp,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactSort {
    pub field: ContactSortField,
    pub direction: SortDirection,
}

impl ContactSort {
    pub const fn new(field: ContactSortField, direction: SortDirection) -> Self {
        Self { field, direction }
    }

    pub const fn default_initiation() -> Self {
        Self {
            field: ContactSortField::InitiationTimestamp,
            direction: SortDirection::Ascending,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-contact-sort/v1",
            &[
                ("field", format!("{:?}", self.field)),
                ("direction", format!("{:?}", self.direction)),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueNextToken {
    raw: String,
}

impl OpaqueNextToken {
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let raw = token.into();
        if !valid_text(&raw, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        Ok(Self { raw })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-opaque-next-token/v1",
            &[("token", self.raw.clone())],
        )
    }
}

impl fmt::Debug for OpaqueNextToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueNextToken")
            .field("token_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SearchCursor {
    scope_digest: Digest,
    query_digest: Digest,
    token: OpaqueNextToken,
    token_digest: Digest,
    page_number: u16,
}

impl SearchCursor {
    pub fn new(
        token: OpaqueNextToken,
        request: &SearchContactsRequest,
        page_number: u16,
    ) -> Result<Self> {
        if page_number <= 1 || page_number > request.max_pages {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            query_digest: request.query_digest.clone(),
            token_digest: token.digest(),
            token,
            page_number,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(&self, request: &SearchContactsRequest) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.query_digest != request.query_digest
            || self.page_number <= 1
            || self.page_number > request.max_pages
            || self.token_digest != self.token.digest()
        {
            return Err(AwsConnectContactResultError::CursorMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for SearchCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchCursor")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for SearchCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SearchCursor", 4)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("queryDigest", &self.query_digest)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SearchContactsRequest {
    scope_digest: Digest,
    expected_provider_digest: Digest,
    expected_registration_digest: Digest,
    time_window: UtcTimeWindow,
    filters: Vec<ContactFilter>,
    sort: ContactSort,
    page_size: u16,
    max_pages: u16,
    attribute_classes: Vec<AttributeKeyClass>,
    cursor: Option<SearchCursor>,
    observed_at: DateTime<Utc>,
    query_digest: Digest,
    request_digest: Digest,
}

impl SearchContactsRequest {
    pub fn new(
        scope: &AwsConnectContactScope,
        time_window: UtcTimeWindow,
        filters: Vec<ContactFilter>,
        sort: ContactSort,
        page_size: u16,
        max_pages: u16,
        attribute_classes: Vec<AttributeKeyClass>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        if time_window != scope.time_window {
            return Err(AwsConnectContactResultError::FilterMismatch);
        }
        if filters.is_empty() || filters.len() > 8 || attribute_classes.len() > MAX_ATTRIBUTES {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        let mut attributes = attribute_classes;
        attributes.sort_unstable();
        attributes.dedup();
        let mut request = Self {
            scope_digest: scope.digest(),
            expected_provider_digest: Digest::from_text("unbound-provider"),
            expected_registration_digest: Digest::from_text("unbound-registration"),
            time_window,
            filters,
            sort,
            page_size,
            max_pages,
            attribute_classes: attributes,
            cursor: None,
            observed_at,
            query_digest: Digest::from_text("unsealed-search-query"),
            request_digest: Digest::from_text("unsealed-search-request"),
        };
        request.validate_against(scope)?;
        request.reseal_digests();
        Ok(request)
    }

    pub fn for_scope(
        scope: &AwsConnectContactScope,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            scope,
            scope.time_window.clone(),
            vec![
                ContactFilter::ContactId(scope.contact.clone()),
                ContactFilter::InstanceId(scope.instance.clone()),
                ContactFilter::QueueId(scope.queue.clone()),
                ContactFilter::AgentId(scope.agent.clone()),
                ContactFilter::Channel(scope.channel),
            ],
            ContactSort::default_initiation(),
            page_size,
            max_pages,
            Vec::new(),
            observed_at,
        )
    }

    pub fn for_scope_with_attributes(
        scope: &AwsConnectContactScope,
        page_size: u16,
        max_pages: u16,
        attribute_classes: Vec<AttributeKeyClass>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            scope,
            scope.time_window.clone(),
            vec![
                ContactFilter::ContactId(scope.contact.clone()),
                ContactFilter::InstanceId(scope.instance.clone()),
                ContactFilter::QueueId(scope.queue.clone()),
                ContactFilter::AgentId(scope.agent.clone()),
                ContactFilter::Channel(scope.channel),
            ],
            ContactSort::default_initiation(),
            page_size,
            max_pages,
            attribute_classes,
            observed_at,
        )
    }

    #[must_use]
    pub fn bind(mut self, provider_digest: Digest, registration_digest: Digest) -> Self {
        self.expected_provider_digest = provider_digest;
        self.expected_registration_digest = registration_digest;
        self.reseal_digests();
        self
    }

    pub fn with_cursor(&self, cursor: SearchCursor) -> Result<Self> {
        cursor.validate_against(self)?;
        let mut next = self.clone();
        next.cursor = Some(cursor);
        next.reseal_digests();
        Ok(next)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn expected_provider_digest(&self) -> &Digest {
        &self.expected_provider_digest
    }

    pub fn expected_registration_digest(&self) -> &Digest {
        &self.expected_registration_digest
    }

    pub fn time_window(&self) -> &UtcTimeWindow {
        &self.time_window
    }

    pub fn filters(&self) -> &[ContactFilter] {
        &self.filters
    }

    pub const fn sort(&self) -> ContactSort {
        self.sort
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub fn attribute_classes(&self) -> &[AttributeKeyClass] {
        &self.attribute_classes
    }

    pub fn cursor(&self) -> Option<&SearchCursor> {
        self.cursor.as_ref()
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, SearchCursor::page_number)
    }

    pub fn cursor_digest(&self) -> Option<Digest> {
        self.cursor
            .as_ref()
            .map(|cursor| cursor.token_digest.clone())
    }

    pub(crate) fn validate_against(&self, scope: &AwsConnectContactScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.time_window != scope.time_window
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
        {
            return Err(AwsConnectContactResultError::FilterMismatch);
        }
        let required = [
            ContactFilter::ContactId(scope.contact.clone()),
            ContactFilter::InstanceId(scope.instance.clone()),
            ContactFilter::QueueId(scope.queue.clone()),
            ContactFilter::AgentId(scope.agent.clone()),
            ContactFilter::Channel(scope.channel),
        ];
        if required.iter().any(|filter| !self.filters.contains(filter)) {
            return Err(AwsConnectContactResultError::FilterMismatch);
        }
        if self.filters.iter().any(|filter| {
            matches!(
                filter.field(),
                ContactFilterField::ContactId
                    | ContactFilterField::InstanceId
                    | ContactFilterField::QueueId
                    | ContactFilterField::AgentId
                    | ContactFilterField::Channel
            ) && !required.contains(filter)
        }) {
            return Err(AwsConnectContactResultError::FilterMismatch);
        }
        if self.attribute_classes.len() > MAX_ATTRIBUTES {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate_against(self)?;
        }
        Ok(())
    }

    fn reseal_digests(&mut self) {
        let filter_digest = Digest::from_parts(
            "aws-connect-contact-filters/v1",
            &[(
                "filters",
                self.filters
                    .iter()
                    .map(|filter| filter.digest().as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        self.query_digest = Digest::from_parts(
            "aws-connect-search-query/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("window", self.time_window.digest().as_str().to_owned()),
                ("filters", filter_digest.as_str().to_owned()),
                ("sort", self.sort.digest().as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                (
                    "attributes",
                    self.attribute_classes
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
            ],
        );
        self.request_digest = Digest::from_parts(
            "aws-connect-search-request/v1",
            &[
                ("query", self.query_digest.as_str().to_owned()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest.as_str().to_owned()),
                ),
                ("page", self.page_number().to_string()),
            ],
        );
    }
}

impl fmt::Debug for SearchContactsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchContactsRequest")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("request_digest", &self.request_digest)
            .field("time_window", &self.time_window)
            .field("filters", &self.filters)
            .field("sort", &self.sort)
            .field("page_size", &self.page_size)
            .field("max_pages", &self.max_pages)
            .field("attribute_classes", &self.attribute_classes)
            .field("cursor", &self.cursor)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SearchContactsResponse {
    request_digest: Digest,
    page_number: u16,
    contacts: Vec<ContactRecord>,
    next_token: Option<OpaqueNextToken>,
    response_bytes: u64,
    provenance: TransportProvenance,
    response_digest: Digest,
}

impl SearchContactsResponse {
    pub fn new(
        request: &SearchContactsRequest,
        contacts: Vec<ContactRecord>,
        next_token: Option<OpaqueNextToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if contacts.len() > usize::from(request.page_size)
            || contacts.len() > usize::from(MAX_PAGE_SIZE)
        {
            return Err(AwsConnectContactResultError::PartialEvidence);
        }
        let response_digest = Digest::from_parts(
            "aws-connect-search-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("page", request.page_number().to_string()),
                (
                    "contacts",
                    contacts
                        .iter()
                        .map(|value| value.digest().as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "next",
                    next_token
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            page_number: request.page_number(),
            contacts,
            next_token,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub fn contacts(&self) -> &[ContactRecord] {
        &self.contacts
    }

    pub fn next_token(&self) -> Option<&OpaqueNextToken> {
        self.next_token.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    pub fn provenance(&self) -> &TransportProvenance {
        &self.provenance
    }

    pub fn validate_integrity(&self, request: &SearchContactsRequest) -> Result<()> {
        if self.request_digest != request.request_digest
            || self.page_number != request.page_number()
            || self.contacts.len() > usize::from(request.page_size)
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        let expected = Self::new(
            request,
            self.contacts.clone(),
            self.next_token.clone(),
            self.response_bytes,
            self.provenance.clone(),
        )?;
        if expected.response_digest != self.response_digest {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for SearchContactsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchContactsResponse")
            .field("request_digest", &self.request_digest)
            .field("page_number", &self.page_number)
            .field("contact_count", &self.contacts.len())
            .field(
                "next_token_digest",
                &self.next_token.as_ref().map(OpaqueNextToken::digest),
            )
            .field("response_bytes", &self.response_bytes)
            .field("provenance", &self.provenance)
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeContactRequest {
    scope_digest: Digest,
    contact: ContactId,
    request_digest: Digest,
}

impl DescribeContactRequest {
    pub fn for_scope(scope: &AwsConnectContactScope) -> Result<Self> {
        let request_digest = Digest::from_parts(
            "aws-connect-describe-contact-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("contact", scope.contact.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            contact: scope.contact.clone(),
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn contact_digest(&self) -> Digest {
        self.contact.digest()
    }

    pub(crate) fn contact(&self) -> &ContactId {
        &self.contact
    }
}

impl fmt::Debug for DescribeContactRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeContactRequest")
            .field("scope_digest", &self.scope_digest)
            .field("contact_digest", &self.contact.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeContactResponse {
    request_digest: Digest,
    contact: ContactRecord,
    response_bytes: u64,
    provenance: TransportProvenance,
    response_digest: Digest,
}

impl DescribeContactResponse {
    pub fn new(
        request: &DescribeContactRequest,
        contact: ContactRecord,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if contact.contact() != request.contact() {
            return Err(AwsConnectContactResultError::ContactReplaced);
        }
        let response_digest = Digest::from_parts(
            "aws-connect-describe-contact-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("contact", contact.digest().as_str().to_owned()),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            contact,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub fn contact(&self) -> &ContactRecord {
        &self.contact
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn provenance(&self) -> &TransportProvenance {
        &self.provenance
    }

    pub fn validate_integrity(&self, request: &DescribeContactRequest) -> Result<()> {
        if self.request_digest != request.request_digest || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        let expected = Self::new(
            request,
            self.contact.clone(),
            self.response_bytes,
            self.provenance.clone(),
        )?;
        if expected.response_digest != self.response_digest {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for DescribeContactResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeContactResponse")
            .field("request_digest", &self.request_digest)
            .field("contact_digest", &self.contact.digest())
            .field("response_bytes", &self.response_bytes)
            .field("provenance", &self.provenance)
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetContactAttributesRequest {
    scope_digest: Digest,
    contact: ContactId,
    key_classes: Vec<AttributeKeyClass>,
    request_digest: Digest,
}

impl GetContactAttributesRequest {
    pub fn for_scope(
        scope: &AwsConnectContactScope,
        mut key_classes: Vec<AttributeKeyClass>,
    ) -> Result<Self> {
        if key_classes.is_empty() || key_classes.len() > MAX_ATTRIBUTES {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        key_classes.sort_unstable();
        key_classes.dedup();
        let request_digest = Digest::from_parts(
            "aws-connect-get-contact-attributes-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("contact", scope.contact.digest().as_str().to_owned()),
                (
                    "keys",
                    key_classes
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            contact: scope.contact.clone(),
            key_classes,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn key_classes(&self) -> &[AttributeKeyClass] {
        &self.key_classes
    }

    pub(crate) fn contact(&self) -> &ContactId {
        &self.contact
    }
}

impl fmt::Debug for GetContactAttributesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetContactAttributesRequest")
            .field("scope_digest", &self.scope_digest)
            .field("contact_digest", &self.contact.digest())
            .field("key_classes", &self.key_classes)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetContactAttributesResponse {
    request_digest: Digest,
    evidence: AttributeEvidenceProjection,
    response_bytes: u64,
    provenance: TransportProvenance,
    response_digest: Digest,
}

impl GetContactAttributesResponse {
    pub fn new(
        request: &GetContactAttributesRequest,
        inputs: Vec<AttributeValueInput>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if inputs
            .iter()
            .any(|input| !request.key_classes.contains(&input.key_class))
        {
            return Err(AwsConnectContactResultError::AttributeNotAllowlisted);
        }
        let evidence = AttributeEvidenceProjection::from_inputs(&inputs)?;
        let response_digest = Digest::from_parts(
            "aws-connect-get-contact-attributes-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("evidence", evidence.evidence_digest.as_str().to_owned()),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            evidence,
            response_bytes,
            provenance,
            response_digest,
        })
    }

    pub fn evidence(&self) -> &AttributeEvidenceProjection {
        &self.evidence
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn provenance(&self) -> &TransportProvenance {
        &self.provenance
    }

    pub fn validate_integrity(&self, request: &GetContactAttributesRequest) -> Result<()> {
        if self.request_digest != request.request_digest || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        let inputs = self
            .evidence
            .attributes
            .iter()
            .map(|value| {
                AttributeValueInput::from_digest(value.key_class, value.value_digest.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let expected = Self::new(
            request,
            inputs,
            self.response_bytes,
            self.provenance.clone(),
        )?;
        if expected.response_digest != self.response_digest {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for GetContactAttributesResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetContactAttributesResponse")
            .field("request_digest", &self.request_digest)
            .field("attribute_evidence", &self.evidence)
            .field("response_bytes", &self.response_bytes)
            .field("provenance", &self.provenance)
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactEvidenceState {
    Completed,
    Partial,
    RetentionExpired,
    AccessLoss,
    ProviderUnknown,
    NotFound,
    Throttled,
    RegistrationRevoked,
}

impl ContactEvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Completed)
    }

    pub const fn is_non_adoptable(self) -> bool {
        !self.is_review_complete()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub sort_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub search_digest: Option<Digest>,
    pub describe_digest: Option<Digest>,
    pub attributes_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionFailure {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub failure_digest: Digest,
}

impl ProjectionFailure {
    pub fn new(
        category: impl Into<String>,
        status_code: Option<u16>,
        retry_after_seconds: Option<u64>,
    ) -> Self {
        let category = category.into();
        let failure_digest = Digest::from_parts(
            "aws-connect-contact-failure/v1",
            &[
                ("category", category.clone()),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "retry_after",
                    retry_after_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            category,
            status_code,
            retry_after_seconds,
            failure_digest,
        }
    }
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsConnectContactResultError::PartialEvidence)
    } else {
        Ok(())
    }
}

pub(crate) fn digest_optional(value: Option<&Digest>) -> String {
    value.map_or_else(String::new, |digest| digest.as_str().to_owned())
}

#[allow(dead_code)]
fn _keep_duration_import() -> Duration {
    Duration::seconds(0)
}
