use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::TwilioHandoffError;

macro_rules! identifier_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TwilioHandoffError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple($label).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = TwilioHandoffError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(ProjectId, "Project ID");
identifier_type!(MissionId, "Mission ID");

macro_rules! twilio_sid_type {
    ($name:ident, $label:literal, [$($prefix:literal),+]) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TwilioHandoffError> {
                let value = value.into();
                validate_sid(&value, $label, &[$($prefix),+])?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple($label).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = TwilioHandoffError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

twilio_sid_type!(TwilioAccountSid, "Twilio Account SID", ["AC"]);
twilio_sid_type!(
    TwilioMessagingServiceSid,
    "Twilio Messaging Service SID",
    ["MG"]
);
twilio_sid_type!(TwilioMessageSid, "Twilio Message SID", ["SM", "MM"]);

macro_rules! digest_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TwilioHandoffError> {
                let value = value.into();
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(TwilioHandoffError::InvalidInput {
                        field: $label,
                        reason: "must be a lowercase SHA-256 hexadecimal digest",
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple($label).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

digest_type!(SourceResultDigest, "source result digest");
digest_type!(IdempotencyFingerprint, "idempotency fingerprint");
digest_type!(RegistrationDigest, "registration digest");

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct E164PhoneNumber(String);

impl E164PhoneNumber {
    pub fn new(value: impl Into<String>) -> Result<Self, TwilioHandoffError> {
        let value = value.into();
        let digits = value
            .strip_prefix('+')
            .ok_or(TwilioHandoffError::InvalidInput {
                field: "recipient",
                reason: "must be an E.164 phone number",
            })?;
        if !(8..=15).contains(&digits.len())
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || digits.starts_with('0')
        {
            return Err(TwilioHandoffError::InvalidInput {
                field: "recipient",
                reason: "must be an E.164 phone number",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn provider_address(&self, channel: TwilioChannel) -> String {
        match channel {
            TwilioChannel::Sms => self.0.clone(),
            TwilioChannel::Whatsapp => format!("whatsapp:{}", self.0),
        }
    }
}

impl fmt::Debug for E164PhoneNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-phone-number>")
    }
}

impl fmt::Display for E164PhoneNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-phone-number>")
    }
}

impl FromStr for E164PhoneNumber {
    type Err = TwilioHandoffError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MessageBody(String);

impl MessageBody {
    pub const MAX_CHARS: usize = 1_600;

    pub fn new(value: impl Into<String>) -> Result<Self, TwilioHandoffError> {
        let value = value.into();
        let char_count = value.chars().count();
        if value.trim().is_empty()
            || char_count > Self::MAX_CHARS
            || value.chars().any(char::is_control)
        {
            return Err(TwilioHandoffError::InvalidInput {
                field: "message body",
                reason: "must be non-empty, bounded, and free of control characters",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> String {
        sha256_hex(self.0.as_bytes())
    }
}

impl fmt::Debug for MessageBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-message-body>")
    }
}

impl fmt::Display for MessageBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-message-body>")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TwilioChannel {
    Sms,
    Whatsapp,
}

impl TwilioChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sms => "sms",
            Self::Whatsapp => "whatsapp",
        }
    }

    pub fn from_provider_value(value: &str) -> Result<Self, TwilioHandoffError> {
        match value {
            "sms" => Ok(Self::Sms),
            "whatsapp" => Ok(Self::Whatsapp),
            _ => Err(TwilioHandoffError::UnsupportedChannel),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum TwilioSenderScope {
    PhoneNumber(E164PhoneNumber),
    MessagingService(TwilioMessagingServiceSid),
}

impl TwilioSenderScope {
    pub(crate) fn canonical_value(&self) -> String {
        match self {
            Self::PhoneNumber(phone) => format!("phone:{}", phone.as_str()),
            Self::MessagingService(service) => format!("messaging_service:{}", service.as_str()),
        }
    }

    pub(crate) fn matches_message_resource(
        &self,
        from: Option<&E164PhoneNumber>,
        messaging_service_sid: Option<&TwilioMessagingServiceSid>,
    ) -> bool {
        match self {
            Self::PhoneNumber(expected) => from == Some(expected),
            Self::MessagingService(expected) => messaging_service_sid == Some(expected),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
}

impl MissionScope {
    pub fn new(project_id: ProjectId, mission_id: MissionId) -> Result<Self, TwilioHandoffError> {
        if project_id.as_str().trim().is_empty() || mission_id.as_str().trim().is_empty() {
            return Err(TwilioHandoffError::InvalidInput {
                field: "Project/Mission scope",
                reason: "must not be empty",
            });
        }
        Ok(Self {
            project_id,
            mission_id,
        })
    }

    pub fn digest(&self) -> String {
        sha256_hex(format!("{}\n{}", self.project_id, self.mission_id).as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwilioScope {
    pub account_id: TwilioAccountSid,
    pub sender: TwilioSenderScope,
    pub channel: TwilioChannel,
    pub recipient: E164PhoneNumber,
    pub mission: MissionScope,
}

impl TwilioScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: TwilioAccountSid,
        sender: TwilioSenderScope,
        channel: TwilioChannel,
        recipient: E164PhoneNumber,
        mission: MissionScope,
    ) -> Result<Self, TwilioHandoffError> {
        let scope = Self {
            account_id,
            sender,
            channel,
            recipient,
            mission,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), TwilioHandoffError> {
        let sender = self.sender.canonical_value();
        if sender.trim().is_empty() {
            return Err(TwilioHandoffError::InvalidInput {
                field: "sender or messaging service",
                reason: "must be present",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.account_id,
            self.sender.canonical_value(),
            self.channel.as_str(),
            self.recipient.as_str(),
            self.mission.project_id,
            self.mission.mission_id
        );
        sha256_hex(canonical.as_bytes())
    }

    pub fn recipient_address(&self) -> String {
        self.recipient.provider_address(self.channel)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffProposalRequest {
    pub scope: TwilioScope,
    pub source_result_digest: SourceResultDigest,
    pub message_body: MessageBody,
}

impl HandoffProposalRequest {
    pub fn new(
        scope: TwilioScope,
        source_result_digest: SourceResultDigest,
        message_body: MessageBody,
    ) -> Result<Self, TwilioHandoffError> {
        scope.validate()?;
        Ok(Self {
            scope,
            source_result_digest,
            message_body,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffProposal {
    pub proposal_version: u32,
    pub mission: MissionScope,
    pub source_result_digest: SourceResultDigest,
    pub scope: TwilioScope,
    pub message_body: MessageBody,
    pub idempotency_fingerprint: IdempotencyFingerprint,
    pub provider_id: String,
    pub provider_version: u32,
    pub registration_digest: RegistrationDigest,
    pub canonical_digest: RegistrationDigest,
    pub mutating: bool,
    pub external_write_performed: bool,
}

impl HandoffProposal {
    pub const VERSION: u32 = 1;

    pub(crate) fn build(
        request: HandoffProposalRequest,
        provider_id: impl Into<String>,
        provider_version: u32,
        registration_digest: RegistrationDigest,
    ) -> Result<Self, TwilioHandoffError> {
        let provider_id = provider_id.into();
        if provider_id.trim().is_empty() {
            return Err(TwilioHandoffError::InvalidInput {
                field: "provider ID",
                reason: "must not be empty",
            });
        }
        let idempotency_material = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            request.scope.mission.project_id,
            request.scope.mission.mission_id,
            request.source_result_digest,
            request.scope.digest(),
            request.scope.channel.as_str(),
            request.scope.recipient.as_str(),
            request.message_body.digest()
        );
        let idempotency_fingerprint =
            IdempotencyFingerprint::new(sha256_hex(idempotency_material.as_bytes()))?;
        let canonical_material = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            Self::VERSION,
            provider_id,
            provider_version,
            registration_digest,
            idempotency_fingerprint,
            request.scope.digest(),
            request.scope.mission.digest(),
            request.source_result_digest,
            request.message_body.digest()
        );
        let canonical_digest = RegistrationDigest::new(sha256_hex(canonical_material.as_bytes()))?;
        Ok(Self {
            proposal_version: Self::VERSION,
            mission: request.scope.mission.clone(),
            source_result_digest: request.source_result_digest,
            scope: request.scope,
            message_body: request.message_body,
            idempotency_fingerprint,
            provider_id,
            provider_version,
            registration_digest,
            canonical_digest,
            mutating: false,
            external_write_performed: false,
        })
    }

    pub fn validate_binding(
        &self,
        registration_digest: &RegistrationDigest,
        scope: &TwilioScope,
    ) -> Result<(), TwilioHandoffError> {
        if &self.registration_digest != registration_digest
            || &self.scope != scope
            || self.mission != scope.mission
            || self.mutating
            || self.external_write_performed
        {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn is_non_mutating(&self) -> bool {
        !self.mutating && !self.external_write_performed
    }

    pub fn message_body_digest(&self) -> String {
        self.message_body.digest()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    NativeHttps,
    Loopback,
    Fixture,
    BlockedEnv,
}

impl EvidenceSource {
    pub const fn is_native(self) -> bool {
        matches!(self, Self::NativeHttps)
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TwilioMessageStatus {
    Accepted,
    Scheduled,
    Queued,
    Sending,
    Sent,
    Delivered,
    PartiallyDelivered,
    Undelivered,
    Failed,
    Read,
    Canceled,
}

impl TwilioMessageStatus {
    pub fn from_provider_value(value: &str) -> Result<Self, TwilioHandoffError> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "scheduled" => Ok(Self::Scheduled),
            "queued" => Ok(Self::Queued),
            "sending" => Ok(Self::Sending),
            "sent" => Ok(Self::Sent),
            "delivered" => Ok(Self::Delivered),
            "partially_delivered" => Ok(Self::PartiallyDelivered),
            "undelivered" => Ok(Self::Undelivered),
            "failed" => Ok(Self::Failed),
            "read" => Ok(Self::Read),
            "canceled" => Ok(Self::Canceled),
            _ => Err(TwilioHandoffError::AmbiguousStatus),
        }
    }

    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Undelivered | Self::Failed | Self::Canceled)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Read | Self::Undelivered | Self::Failed | Self::Canceled
        )
    }

    pub const fn can_advance_to(self, next: Self) -> bool {
        if self as u8 == next as u8 {
            return true;
        }
        match self {
            Self::Accepted | Self::Scheduled => matches!(
                next,
                Self::Queued
                    | Self::Sending
                    | Self::Sent
                    | Self::Delivered
                    | Self::PartiallyDelivered
                    | Self::Read
                    | Self::Undelivered
                    | Self::Failed
                    | Self::Canceled
            ),
            Self::Queued => matches!(
                next,
                Self::Sending
                    | Self::Sent
                    | Self::Delivered
                    | Self::PartiallyDelivered
                    | Self::Read
                    | Self::Undelivered
                    | Self::Failed
            ),
            Self::Sending => matches!(
                next,
                Self::Sent
                    | Self::Delivered
                    | Self::PartiallyDelivered
                    | Self::Read
                    | Self::Undelivered
                    | Self::Failed
            ),
            Self::Sent => matches!(
                next,
                Self::Delivered
                    | Self::PartiallyDelivered
                    | Self::Read
                    | Self::Undelivered
                    | Self::Failed
            ),
            Self::PartiallyDelivered => matches!(next, Self::Delivered | Self::Read),
            Self::Delivered => matches!(next, Self::Read),
            Self::Read | Self::Undelivered | Self::Failed | Self::Canceled => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusEvidence {
    Fixture,
    Loopback,
    VerifiedCallback { source: EvidenceSource },
    NativeReadback,
}

impl StatusEvidence {
    pub const fn source(self) -> EvidenceSource {
        match self {
            Self::Fixture => EvidenceSource::Fixture,
            Self::Loopback => EvidenceSource::Loopback,
            Self::VerifiedCallback { source } => source,
            Self::NativeReadback => EvidenceSource::NativeHttps,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryStatusProjection {
    pub status: TwilioMessageStatus,
    pub observed_at_ms: u64,
    pub evidence: StatusEvidence,
    pub monotonic: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptReadRequest {
    pub scope_digest: RegistrationDigest,
    pub registration_digest: RegistrationDigest,
    pub idempotency_fingerprint: IdempotencyFingerprint,
    pub provider_message_sid: Option<TwilioMessageSid>,
}

impl ReceiptReadRequest {
    pub fn new(
        scope_digest: RegistrationDigest,
        registration_digest: RegistrationDigest,
        idempotency_fingerprint: IdempotencyFingerprint,
        provider_message_sid: Option<TwilioMessageSid>,
    ) -> Self {
        Self {
            scope_digest,
            registration_digest,
            idempotency_fingerprint,
            provider_message_sid,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryStatusRequest {
    pub scope_digest: RegistrationDigest,
    pub registration_digest: RegistrationDigest,
    pub idempotency_fingerprint: IdempotencyFingerprint,
    pub provider_message_sid: TwilioMessageSid,
    pub next_status: TwilioMessageStatus,
    pub observed_at_ms: u64,
    pub evidence: StatusEvidence,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TwilioMessageReceipt {
    pub(crate) provider_message_sid: TwilioMessageSid,
    pub(crate) binding: ReceiptBinding,
    pub(crate) status: DeliveryStatusProjection,
    pub(crate) scope: TwilioScope,
    pub(crate) message_body_digest: String,
    pub(crate) evidence_source: EvidenceSource,
    pub(crate) external_write_performed: bool,
}

impl TwilioMessageReceipt {
    pub fn provider_message_sid(&self) -> &TwilioMessageSid {
        &self.provider_message_sid
    }

    pub fn status(&self) -> &DeliveryStatusProjection {
        &self.status
    }

    pub fn scope(&self) -> &TwilioScope {
        &self.scope
    }

    pub fn message_body_digest(&self) -> &str {
        &self.message_body_digest
    }

    pub fn evidence_source(&self) -> EvidenceSource {
        self.evidence_source
    }

    pub fn external_write_performed(&self) -> bool {
        self.external_write_performed
    }

    pub fn redacted(&self) -> RedactedHandoffReceipt {
        RedactedHandoffReceipt {
            provider_message_sid: self.provider_message_sid.clone(),
            provider_version: self.binding.provider_version,
            registration_digest: self.binding.registration_digest.clone(),
            scope_digest: self.binding.scope_digest.clone(),
            mission_digest: self.binding.mission_digest.clone(),
            source_result_digest: self.binding.source_result_digest.clone(),
            idempotency_fingerprint: self.binding.idempotency_fingerprint.clone(),
            channel: self.scope.channel,
            status: self.status.clone(),
            evidence_source: self.evidence_source,
            external_write_performed: self.external_write_performed,
            redactions: ReceiptRedactions::default(),
        }
    }
}

impl fmt::Debug for TwilioMessageReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwilioMessageReceipt")
            .field("redacted", &self.redacted())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptBinding {
    pub(crate) provider_version: u32,
    pub(crate) registration_digest: RegistrationDigest,
    pub(crate) scope_digest: RegistrationDigest,
    pub(crate) mission_digest: String,
    pub(crate) source_result_digest: SourceResultDigest,
    pub(crate) idempotency_fingerprint: IdempotencyFingerprint,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptRedactions {
    pub phone_numbers: bool,
    pub message_bodies: bool,
    pub auth_material: bool,
    pub callback_payloads: bool,
    pub provider_tokens: bool,
}

impl Default for ReceiptRedactions {
    fn default() -> Self {
        Self {
            phone_numbers: true,
            message_bodies: true,
            auth_material: true,
            callback_payloads: true,
            provider_tokens: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedHandoffReceipt {
    pub provider_message_sid: TwilioMessageSid,
    pub provider_version: u32,
    pub registration_digest: RegistrationDigest,
    pub scope_digest: RegistrationDigest,
    pub mission_digest: String,
    pub source_result_digest: SourceResultDigest,
    pub idempotency_fingerprint: IdempotencyFingerprint,
    pub channel: TwilioChannel,
    pub status: DeliveryStatusProjection,
    pub evidence_source: EvidenceSource,
    pub external_write_performed: bool,
    pub redactions: ReceiptRedactions,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub provider_id: String,
    pub account_id: TwilioAccountSid,
    pub reference_id: String,
}

impl SecretReference {
    pub fn new(
        account_id: TwilioAccountSid,
        reference_id: impl Into<String>,
    ) -> Result<Self, TwilioHandoffError> {
        let reference_id = reference_id.into();
        validate_identifier(&reference_id, "secret reference ID")?;
        Ok(Self {
            provider_id: String::from("twilio"),
            account_id,
            reference_id,
        })
    }

    pub fn fixture(account_id: TwilioAccountSid) -> Self {
        Self {
            provider_id: String::from("twilio"),
            account_id,
            reference_id: String::from("fixture-secret-reference"),
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("provider_id", &self.provider_id)
            .field("account_id", &self.account_id)
            .field("reference_id", &"<redacted-reference>")
            .finish()
    }
}

/// Secret bytes are borrowed by a transport for one operation and are never
/// serialized or retained by a provider registration.
pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, TwilioHandoffError> {
        let value = value.as_ref();
        if value.is_empty() || value.iter().any(u8::is_ascii_control) {
            return Err(TwilioHandoffError::InvalidInput {
                field: "secret material",
                reason: "must be non-empty and free of control characters",
            });
        }
        Ok(Self(value.to_vec()))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-secret-material>")
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TwilioCallbackSignature(String);

impl TwilioCallbackSignature {
    pub fn new(value: impl Into<String>) -> Result<Self, TwilioHandoffError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(TwilioHandoffError::InvalidInput {
                field: "Twilio callback signature",
                reason: "must be non-empty ASCII text",
            });
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TwilioCallbackSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-callback-signature>")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TwilioCallbackRequest {
    pub callback_url: Url,
    pub signature: TwilioCallbackSignature,
    pub form_parameters: BTreeMap<String, String>,
    pub event_at_ms: u64,
    pub received_at_ms: u64,
}

impl fmt::Debug for TwilioCallbackRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwilioCallbackRequest")
            .field("callback_url", &"<redacted-callback-url>")
            .field("signature", &self.signature)
            .field(
                "form_parameter_names",
                &self.form_parameters.keys().collect::<Vec<_>>(),
            )
            .field("event_at_ms", &self.event_at_ms)
            .field("received_at_ms", &self.received_at_ms)
            .finish()
    }
}

impl TwilioCallbackRequest {
    pub fn new(
        callback_url: impl AsRef<str>,
        signature: TwilioCallbackSignature,
        form_parameters: BTreeMap<String, String>,
        event_at_ms: u64,
        received_at_ms: u64,
    ) -> Result<Self, TwilioHandoffError> {
        let callback_url =
            Url::parse(callback_url.as_ref()).map_err(|_| TwilioHandoffError::InvalidInput {
                field: "callback URL",
                reason: "must be an HTTPS URL without credentials",
            })?;
        if callback_url.scheme() != "https"
            || callback_url.host_str().is_none()
            || !callback_url.username().is_empty()
            || callback_url.password().is_some()
            || callback_url.fragment().is_some()
            || form_parameters
                .keys()
                .any(|key| key.chars().any(char::is_control))
            || form_parameters
                .values()
                .any(|value| value.chars().any(char::is_control))
        {
            return Err(TwilioHandoffError::InvalidInput {
                field: "callback request",
                reason: "contains an invalid URL or control character",
            });
        }
        if event_at_ms == 0 || received_at_ms == 0 {
            return Err(TwilioHandoffError::InvalidInput {
                field: "callback timestamp",
                reason: "must be non-zero",
            });
        }
        Ok(Self {
            callback_url,
            signature,
            form_parameters,
            event_at_ms,
            received_at_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedInboundSignal {
    pub provider_message_sid: TwilioMessageSid,
    pub account_id: TwilioAccountSid,
    pub status: TwilioMessageStatus,
    pub idempotency_fingerprint: IdempotencyFingerprint,
    pub callback_digest: RegistrationDigest,
    pub observed_at_ms: u64,
    pub evidence: StatusEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwilioReadRequest {
    pub account_id: TwilioAccountSid,
    pub provider_message_sid: TwilioMessageSid,
}

impl TwilioReadRequest {
    pub fn new(account_id: TwilioAccountSid, provider_message_sid: TwilioMessageSid) -> Self {
        Self {
            account_id,
            provider_message_sid,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwilioCreateMessageRequest {
    pub account_id: TwilioAccountSid,
    pub channel: TwilioChannel,
    pub sender: TwilioSenderScope,
    pub recipient: E164PhoneNumber,
    pub message_body: MessageBody,
    pub idempotency_fingerprint: IdempotencyFingerprint,
    pub status_callback_url: Option<Url>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TwilioMessageResource {
    pub sid: TwilioMessageSid,
    pub account_sid: TwilioAccountSid,
    pub status: TwilioMessageStatus,
    pub to: String,
    pub from: Option<String>,
    pub messaging_service_sid: Option<TwilioMessagingServiceSid>,
    pub error_code: Option<u32>,
}

impl TwilioMessageResource {
    pub fn validate_against(&self, scope: &TwilioScope) -> Result<(), TwilioHandoffError> {
        if self.account_sid != scope.account_id {
            return Err(TwilioHandoffError::CallbackScopeMismatch);
        }
        let to = normalize_provider_phone(&self.to)?;
        if to != scope.recipient {
            return Err(TwilioHandoffError::CallbackScopeMismatch);
        }
        let from = self
            .from
            .as_deref()
            .map(normalize_provider_phone)
            .transpose()?;
        if !scope
            .sender
            .matches_message_resource(from.as_ref(), self.messaging_service_sid.as_ref())
        {
            return Err(TwilioHandoffError::CallbackScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for TwilioMessageResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwilioMessageResource")
            .field("sid", &self.sid)
            .field("account_sid", &"<redacted-account>")
            .field("status", &self.status)
            .field("to", &"<redacted-phone-number>")
            .field("from", &"<redacted-phone-number>")
            .field("messaging_service_sid", &self.messaging_service_sid)
            .field("error_code", &self.error_code)
            .finish()
    }
}

pub(crate) fn normalize_provider_phone(value: &str) -> Result<E164PhoneNumber, TwilioHandoffError> {
    let value = value.strip_prefix("whatsapp:").unwrap_or(value);
    E164PhoneNumber::new(value.to_owned())
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), TwilioHandoffError> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(TwilioHandoffError::InvalidInput {
            field,
            reason: "must be non-empty, bounded, and free of whitespace/control characters",
        });
    }
    Ok(())
}

pub(crate) fn validate_sid(
    value: &str,
    field: &'static str,
    prefixes: &[&str],
) -> Result<(), TwilioHandoffError> {
    if value.len() != 34
        || !prefixes.iter().any(|prefix| value.starts_with(prefix))
        || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TwilioHandoffError::InvalidInput {
            field,
            reason: "must be a valid Twilio SID",
        });
    }
    Ok(())
}

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn callback_canonical_material(
    callback_url: &Url,
    form_parameters: &BTreeMap<String, String>,
) -> String {
    let mut material = callback_url.as_str().to_owned();
    for (name, value) in form_parameters {
        material.push_str(name);
        material.push_str(value);
    }
    material
}

pub(crate) fn callback_digest(
    callback_url: &Url,
    form_parameters: &BTreeMap<String, String>,
) -> RegistrationDigest {
    RegistrationDigest::new(sha256_hex(
        callback_canonical_material(callback_url, form_parameters).as_bytes(),
    ))
    .expect("SHA-256 callback digest is always valid")
}
