use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{ModelError, ModelResult};
use crate::{
    MAX_DIAGNOSTIC_BYTES, MAX_EVENTS_PER_PAGE, MAX_IDENTIFIER_BYTES, MAX_PAGES, MAX_RESPONSE_BYTES,
    MAX_RETRY_AFTER_SECONDS, MAX_TAG_BYTES, MAX_TAGS, MAX_TOTAL_EVENTS, MAX_WEBHOOK_AGE_SECONDS,
};

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Mailgun typed value serializes");
    sha256_digest(&bytes)
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_revision(value: u64, label: &'static str) -> ModelResult<()> {
    if value == 0 {
        Err(ModelError::InvalidRevision { label })
    } else {
        Ok(())
    }
}

macro_rules! redacted_text {
    ($name:ident, $label:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> ModelResult<Self> {
                let value = value.into();
                if !($validator)(&value) {
                    return Err(ModelError::InvalidIdentifier { label: $label });
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                sha256_digest(format!("mailgun-{}-v1|{}", $label, self.0).as_bytes())
            }

            #[must_use]
            pub fn redacted(&self) -> String {
                format!("{}:{}", $label, &self.digest()[..16])
            }

            pub(crate) fn validate(&self) -> ModelResult<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(ModelError::InvalidIdentifier { label: $label })
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.digest())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }
    };
}

redacted_text!(MailgunAccountId, "account", |value: &str| {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
});
redacted_text!(MailgunDomain, "domain", |value: &str| {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
});
redacted_text!(MailgunTag, "tag", |value: &str| {
    valid_text(value, MAX_TAG_BYTES, true)
});
redacted_text!(MailgunMessageId, "message-id", |value: &str| {
    valid_text(value, MAX_IDENTIFIER_BYTES, true)
});
redacted_text!(MailgunEventId, "event-id", |value: &str| {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
});

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !valid_text(&value, MAX_IDENTIFIER_BYTES, false)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(ModelError::InvalidIdentifier {
                label: "identifier",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> ModelResult<Self> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> ModelResult<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> ModelResult<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> ModelResult<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub consent_digest: Digest,
    pub revision: Revision,
    pub expires_at_seconds: Option<u64>,
}

impl ConsentScope {
    pub fn new(reference: impl Into<String>, revision: u64) -> ModelResult<Self> {
        Self::with_expiry(reference, revision, None)
    }

    pub fn with_expiry(
        reference: impl Into<String>,
        revision: u64,
        expires_at_seconds: Option<u64>,
    ) -> ModelResult<Self> {
        let reference = reference.into();
        if !valid_text(&reference, MAX_IDENTIFIER_BYTES, false) {
            return Err(ModelError::InvalidConsent);
        }
        Ok(Self {
            consent_digest: sha256_digest(format!("mailgun-consent/v1|{reference}").as_bytes()),
            revision: Revision::new(revision)?,
            expires_at_seconds,
        })
    }

    pub fn from_digest(
        consent_digest: impl Into<String>,
        revision: u64,
        expires_at_seconds: Option<u64>,
    ) -> ModelResult<Self> {
        let consent_digest = consent_digest.into();
        if !valid_digest(&consent_digest) {
            return Err(ModelError::InvalidConsent);
        }
        Ok(Self {
            consent_digest,
            revision: Revision::new(revision)?,
            expires_at_seconds,
        })
    }

    pub fn validate_at(&self, now_seconds: u64) -> ModelResult<()> {
        if !valid_digest(&self.consent_digest)
            || self
                .expires_at_seconds
                .is_some_and(|expires_at| now_seconds > expires_at)
        {
            return Err(ModelError::InvalidConsent);
        }
        validate_revision(self.revision.get(), "consent")
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn is_expired(&self, now_seconds: u64) -> bool {
        self.expires_at_seconds
            .is_some_and(|expires_at| now_seconds > expires_at)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailgunEventKind {
    Accepted,
    Delivered,
    TemporaryFailure,
    PermanentFailure,
    Complained,
    Unsubscribed,
    Opened,
    Clicked,
    Stored,
    Suppressed,
    Unknown,
}

impl MailgunEventKind {
    #[must_use]
    pub const fn delivery_status(&self) -> DeliveryStatus {
        match self {
            Self::Accepted | Self::Stored => DeliveryStatus::Accepted,
            Self::Delivered => DeliveryStatus::Delivered,
            Self::TemporaryFailure => DeliveryStatus::TemporaryFailure,
            Self::PermanentFailure => DeliveryStatus::PermanentFailure,
            Self::Suppressed | Self::Unsubscribed | Self::Complained => DeliveryStatus::Suppressed,
            Self::Opened | Self::Clicked | Self::Unknown => DeliveryStatus::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Accepted,
    Delivered,
    TemporaryFailure,
    PermanentFailure,
    Suppressed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecipientFingerprint(Digest);

impl RecipientFingerprint {
    pub fn from_recipient(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !valid_text(&value, MAX_IDENTIFIER_BYTES, false) || !value.contains('@') {
            return Err(ModelError::InvalidIdentifier { label: "recipient" });
        }
        Ok(Self(sha256_digest(
            format!("mailgun-recipient-fingerprint/v1|{value}").as_bytes(),
        )))
    }

    pub fn from_digest(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunMessageSelector {
    pub message_id_digest: Option<Digest>,
}

impl MailgunMessageSelector {
    #[must_use]
    pub const fn any() -> Self {
        Self {
            message_id_digest: None,
        }
    }

    #[must_use]
    pub fn message(message_id: &MailgunMessageId) -> Self {
        Self {
            message_id_digest: Some(message_id.digest()),
        }
    }

    pub fn from_message_id(value: impl Into<String>) -> ModelResult<Self> {
        Ok(Self::message(&MailgunMessageId::new(value)?))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum MailgunEventSelector {
    Any,
    EventIdDigest(Digest),
    Kind(MailgunEventKind),
}

impl MailgunEventSelector {
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    pub fn event(event_id: &MailgunEventId) -> Self {
        Self::EventIdDigest(event_id.digest())
    }

    pub fn from_event_id(value: impl Into<String>) -> ModelResult<Self> {
        Ok(Self::event(&MailgunEventId::new(value)?))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunDeliveryResultScopeSpec {
    pub account: MailgunAccountId,
    pub domain: MailgunDomain,
    pub tags: Vec<MailgunTag>,
    pub message: MailgunMessageSelector,
    pub event: MailgunEventSelector,
    pub recipient: Option<RecipientFingerprint>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub scope_revision: Revision,
    pub provider_revision: Revision,
}

#[allow(clippy::too_many_arguments)]
impl MailgunDeliveryResultScopeSpec {
    #[must_use]
    pub fn new(
        account: MailgunAccountId,
        domain: MailgunDomain,
        tags: Vec<MailgunTag>,
        message: MailgunMessageSelector,
        event: MailgunEventSelector,
        recipient: Option<RecipientFingerprint>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
        scope_revision: Revision,
        provider_revision: Revision,
    ) -> Self {
        Self {
            account,
            domain,
            tags,
            message,
            event,
            recipient,
            project,
            mission,
            work_product,
            consent,
            scope_revision,
            provider_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunDeliveryResultScope {
    pub account: MailgunAccountId,
    pub domain: MailgunDomain,
    pub tags: Vec<MailgunTag>,
    pub message: MailgunMessageSelector,
    pub event: MailgunEventSelector,
    pub recipient: Option<RecipientFingerprint>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub scope_revision: Revision,
    pub provider_revision: Revision,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
}

impl MailgunDeliveryResultScope {
    pub fn new(spec: MailgunDeliveryResultScopeSpec) -> ModelResult<Self> {
        if spec.tags.len() > MAX_TAGS {
            return Err(ModelError::InvalidScope("tags"));
        }
        for tag in &spec.tags {
            tag.validate()?;
        }
        let tag_digests = spec
            .tags
            .iter()
            .map(MailgunTag::digest)
            .collect::<BTreeSet<_>>();
        if tag_digests.len() != spec.tags.len() {
            return Err(ModelError::InvalidScope("duplicate tags"));
        }
        spec.account.validate()?;
        spec.domain.validate()?;
        spec.consent.validate_at(0)?;
        validate_revision(spec.scope_revision.get(), "scope")?;
        validate_revision(spec.provider_revision.get(), "provider")?;
        let scope_digest = scope_digest(&spec);
        let revision_digest = revision_digest(&spec);
        let privacy_digest = privacy_digest(&spec);
        Ok(Self {
            account: spec.account,
            domain: spec.domain,
            tags: spec.tags,
            message: spec.message,
            event: spec.event,
            recipient: spec.recipient,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            consent: spec.consent,
            scope_revision: spec.scope_revision,
            provider_revision: spec.provider_revision,
            scope_digest,
            revision_digest,
            privacy_digest,
        })
    }

    pub fn validate(&self) -> ModelResult<()> {
        let spec = self.spec();
        if scope_digest(&spec) != self.scope_digest
            || revision_digest(&spec) != self.revision_digest
            || privacy_digest(&spec) != self.privacy_digest
        {
            return Err(ModelError::InvalidScope("digest fence"));
        }
        self.consent.validate_at(0)
    }

    #[must_use]
    pub fn spec(&self) -> MailgunDeliveryResultScopeSpec {
        MailgunDeliveryResultScopeSpec {
            account: self.account.clone(),
            domain: self.domain.clone(),
            tags: self.tags.clone(),
            message: self.message.clone(),
            event: self.event.clone(),
            recipient: self.recipient.clone(),
            project: self.project.clone(),
            mission: self.mission.clone(),
            work_product: self.work_product.clone(),
            consent: self.consent.clone(),
            scope_revision: self.scope_revision,
            provider_revision: self.provider_revision,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn privacy_digest(&self) -> &Digest {
        &self.privacy_digest
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent.consent_digest
    }

    #[must_use]
    pub fn tag_digests(&self) -> Vec<Digest> {
        self.tags.iter().map(MailgunTag::digest).collect()
    }
}

fn scope_digest(spec: &MailgunDeliveryResultScopeSpec) -> Digest {
    canonical_digest(&(
        "mailgun-delivery-result-scope/v1",
        &spec.account,
        &spec.domain,
        spec.tags.iter().map(MailgunTag::digest).collect::<Vec<_>>(),
        &spec.message,
        &spec.event,
        &spec.recipient,
        &spec.project,
        &spec.mission,
        &spec.work_product,
        &spec.consent,
        spec.scope_revision,
        spec.provider_revision,
    ))
}

fn revision_digest(spec: &MailgunDeliveryResultScopeSpec) -> Digest {
    canonical_digest(&(
        "mailgun-delivery-result-revisions/v1",
        spec.scope_revision,
        spec.provider_revision,
        spec.project.revision,
        spec.mission.revision,
        spec.work_product.revision,
        spec.consent.revision,
    ))
}

fn privacy_digest(spec: &MailgunDeliveryResultScopeSpec) -> Digest {
    canonical_digest(&(
        "mailgun-delivery-result-privacy/v1",
        spec.tags.iter().map(MailgunTag::digest).collect::<Vec<_>>(),
        &spec.message,
        &spec.event,
        &spec.recipient,
        "raw_message_body_dropped",
        "raw_event_payload_dropped",
        "raw_recipient_dropped",
        "raw_webhook_material_dropped",
    ))
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_handle: String,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> ModelResult<Self> {
        let opaque_handle = opaque_handle.into();
        if !valid_text(&opaque_handle, MAX_IDENTIFIER_BYTES, false) {
            return Err(ModelError::InvalidIdentifier {
                label: "secret reference",
            });
        }
        Ok(Self {
            opaque_handle,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn api_key(opaque_handle: impl Into<String>, revision: u64) -> ModelResult<Self> {
        Self::new(opaque_handle, revision)
    }

    pub fn webhook_signing_key(
        opaque_handle: impl Into<String>,
        revision: u64,
    ) -> ModelResult<Self> {
        Self::new(opaque_handle, revision)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "mailgun-secret-reference/v1|{}|{}",
                self.opaque_handle,
                self.revision.get()
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> ModelResult<()> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> ModelResult<()> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque_handle", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    raw: String,
    digest: Digest,
}

impl Cursor {
    pub fn new(raw: impl Into<String>) -> ModelResult<Self> {
        let raw = raw.into();
        if !valid_text(&raw, MAX_IDENTIFIER_BYTES, false) {
            return Err(ModelError::InvalidCursor);
        }
        let digest = sha256_digest(format!("mailgun-cursor/v1|{raw}").as_bytes());
        Ok(Self { raw, digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> ModelResult<()> {
        if valid_text(&self.raw, MAX_IDENTIFIER_BYTES, false)
            && sha256_digest(format!("mailgun-cursor/v1|{}", self.raw).as_bytes()) == self.digest
        {
            Ok(())
        } else {
            Err(ModelError::InvalidCursor)
        }
    }
}

impl Serialize for Cursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.digest)
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Cursor")
            .field(&format_args!("{}…", &self.digest[..16]))
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(&self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryMetadata {
    pub attempt_count: u16,
    pub retry_after_seconds: Option<u32>,
    pub backoff_seconds: Option<u32>,
    pub exhausted: bool,
}

impl RetryMetadata {
    pub fn new(
        attempt_count: u16,
        retry_after_seconds: Option<u32>,
        backoff_seconds: Option<u32>,
        exhausted: bool,
    ) -> ModelResult<Self> {
        if attempt_count > 100
            || retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
            || backoff_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(ModelError::InvalidRetry);
        }
        Ok(Self {
            attempt_count,
            retry_after_seconds,
            backoff_seconds,
            exhausted,
        })
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.attempt_count > 100
            || self
                .retry_after_seconds
                .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
            || self
                .backoff_seconds
                .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
        {
            Err(ModelError::InvalidRetry)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionCategory {
    Bounce,
    Complaint,
    Unsubscribe,
    DeliveryFailure,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuppressionMetadata {
    pub category: SuppressionCategory,
    pub active: bool,
    pub reason_digest: Option<Digest>,
}

impl SuppressionMetadata {
    pub fn new(
        category: SuppressionCategory,
        active: bool,
        reason: Option<String>,
    ) -> ModelResult<Self> {
        let reason_digest = reason
            .map(|value| {
                if !valid_text(&value, MAX_DIAGNOSTIC_BYTES, true) {
                    return Err(ModelError::InvalidSuppression);
                }
                Ok(sha256_digest(
                    format!("mailgun-suppression-reason/v1|{value}").as_bytes(),
                ))
            })
            .transpose()?;
        Ok(Self {
            category,
            active,
            reason_digest,
        })
    }

    pub fn with_reason(
        category: SuppressionCategory,
        active: bool,
        reason: impl Into<String>,
    ) -> ModelResult<Self> {
        Self::new(category, active, Some(reason.into()))
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self
            .reason_digest
            .as_ref()
            .is_some_and(|value| !valid_digest(value))
        {
            Err(ModelError::InvalidSuppression)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunDeliveryEvent {
    pub event_id: MailgunEventId,
    pub message_id: MailgunMessageId,
    pub recipient: RecipientFingerprint,
    pub kind: MailgunEventKind,
    pub occurred_at_seconds: u64,
    pub tag_digests: Vec<Digest>,
    pub retry: RetryMetadata,
    pub suppression: Option<SuppressionMetadata>,
    pub event_digest: Digest,
}

impl MailgunDeliveryEvent {
    pub fn new(
        event_id: MailgunEventId,
        message_id: MailgunMessageId,
        recipient: RecipientFingerprint,
        kind: MailgunEventKind,
        occurred_at_seconds: u64,
        tags: Vec<MailgunTag>,
        retry: RetryMetadata,
        suppression: Option<SuppressionMetadata>,
    ) -> ModelResult<Self> {
        if tags.len() > MAX_TAGS
            || tags
                .iter()
                .map(MailgunTag::digest)
                .collect::<BTreeSet<_>>()
                .len()
                != tags.len()
        {
            return Err(ModelError::InvalidEvent);
        }
        let tag_digests = tags.iter().map(MailgunTag::digest).collect::<Vec<_>>();
        let event_digest = event_digest(
            &event_id,
            &message_id,
            &recipient,
            &kind,
            occurred_at_seconds,
            &tag_digests,
            &retry,
            suppression.as_ref(),
        );
        Ok(Self {
            event_id,
            message_id,
            recipient,
            kind,
            occurred_at_seconds,
            tag_digests,
            retry,
            suppression,
            event_digest,
        })
    }

    pub fn fixture(
        event_id: impl Into<String>,
        message_id: impl Into<String>,
        recipient: impl Into<String>,
        kind: MailgunEventKind,
        occurred_at_seconds: u64,
    ) -> ModelResult<Self> {
        Self::new(
            MailgunEventId::new(event_id)?,
            MailgunMessageId::new(message_id)?,
            RecipientFingerprint::from_recipient(recipient)?,
            kind,
            occurred_at_seconds,
            Vec::new(),
            RetryMetadata::default(),
            None,
        )
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.event_id.validate()?;
        self.message_id.validate()?;
        if !valid_digest(self.recipient.digest())
            || self.tag_digests.len() > MAX_TAGS
            || self.tag_digests.iter().any(|value| !valid_digest(value))
            || self.retry.validate().is_err()
            || self
                .suppression
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            || event_digest(
                &self.event_id,
                &self.message_id,
                &self.recipient,
                &self.kind,
                self.occurred_at_seconds,
                &self.tag_digests,
                &self.retry,
                self.suppression.as_ref(),
            ) != self.event_digest
        {
            return Err(ModelError::InvalidEvent);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.event_digest
    }

    #[must_use]
    pub const fn status(&self) -> DeliveryStatus {
        self.kind.delivery_status()
    }
}

pub type MailgunEvent = MailgunDeliveryEvent;

fn event_digest(
    event_id: &MailgunEventId,
    message_id: &MailgunMessageId,
    recipient: &RecipientFingerprint,
    kind: &MailgunEventKind,
    occurred_at_seconds: u64,
    tag_digests: &[Digest],
    retry: &RetryMetadata,
    suppression: Option<&SuppressionMetadata>,
) -> Digest {
    canonical_digest(&(
        "mailgun-delivery-event/v1",
        event_id,
        message_id,
        recipient,
        kind,
        occurred_at_seconds,
        tag_digests,
        retry,
        suppression,
    ))
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitReceipt {
    pub limit: u32,
    pub remaining: Option<u32>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl RateLimitReceipt {
    pub fn new(
        limit: u32,
        remaining: Option<u32>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> ModelResult<Self> {
        if limit == 0
            || remaining.is_some_and(|value| value > limit)
            || retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(ModelError::InvalidRateLimit);
        }
        Ok(Self {
            limit,
            remaining,
            retry_after_seconds,
            throttled,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.limit != 0
            && (self.remaining.is_some_and(|value| value > self.limit)
                || self
                    .retry_after_seconds
                    .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS))
        {
            Err(ModelError::InvalidRateLimit)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackoffReceipt {
    pub attempt: u16,
    pub retryable: bool,
    pub retry_after_seconds: Option<u32>,
    pub backoff_digest: Digest,
}

impl BackoffReceipt {
    #[must_use]
    pub fn none() -> Self {
        Self {
            attempt: 0,
            retryable: false,
            retry_after_seconds: None,
            backoff_digest: canonical_digest(&"mailgun-no-backoff/v1"),
        }
    }

    pub fn new(
        attempt: u16,
        retryable: bool,
        retry_after_seconds: Option<u32>,
    ) -> ModelResult<Self> {
        if retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS) {
            return Err(ModelError::InvalidRetry);
        }
        let backoff_digest = canonical_digest(&(
            "mailgun-backoff/v1",
            attempt,
            retryable,
            retry_after_seconds,
        ));
        Ok(Self {
            attempt,
            retryable,
            retry_after_seconds,
            backoff_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Ready,
    Partial,
    Empty,
    Denied,
    Expired,
    RateLimited,
    ProviderUnknown,
    Tampered,
    ReplayRejected,
    PaginationLoop,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Normalized,
    Partial,
    Empty,
    Denied,
    Expired,
    RateLimited,
    ProviderUnknown,
    Tampered,
    Replay,
    PaginationLoop,
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunRequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub page: u16,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub redacted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub events_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub webhook_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookVerificationState {
    Verified,
    Tampered,
    Replay,
    Expired,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MailgunWebhookEnvelope {
    event_id_digest: Digest,
    timestamp_seconds: u64,
    token_digest: Digest,
    payload_digest: Digest,
    signed_material_digest: Digest,
    signature_digest: Digest,
    replay_key_digest: Digest,
}

impl MailgunWebhookEnvelope {
    pub fn fixture(
        event_id: impl Into<String>,
        timestamp_seconds: u64,
        token: impl Into<String>,
        event: &MailgunDeliveryEvent,
    ) -> ModelResult<Self> {
        let event_id = MailgunEventId::new(event_id)?;
        let token = token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, false) {
            return Err(ModelError::InvalidWebhook);
        }
        let event_id_digest = event_id.digest();
        let token_digest = sha256_digest(format!("mailgun-webhook-token/v1|{token}").as_bytes());
        let payload_digest = event.digest().clone();
        let signed_material_digest = canonical_digest(&(
            "mailgun-webhook-material/v1",
            &event_id_digest,
            timestamp_seconds,
            &token_digest,
            &payload_digest,
        ));
        let signature_digest = sha256_digest(
            format!("mailgun-webhook-signature/v1|{signed_material_digest}").as_bytes(),
        );
        let replay_key_digest =
            canonical_digest(&("mailgun-webhook-replay/v1", &event_id_digest, &token_digest));
        Ok(Self {
            event_id_digest,
            timestamp_seconds,
            token_digest,
            payload_digest,
            signed_material_digest,
            signature_digest,
            replay_key_digest,
        })
    }

    #[must_use]
    pub fn tampered(&self) -> Self {
        let mut tampered = self.clone();
        tampered.payload_digest =
            canonical_digest(&("mailgun-tampered-payload/v1", &self.payload_digest));
        tampered
    }

    #[must_use]
    pub fn replay_key_digest(&self) -> &Digest {
        &self.replay_key_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn verify(&self, now_seconds: u64) -> WebhookVerificationState {
        let expected_material = canonical_digest(&(
            "mailgun-webhook-material/v1",
            &self.event_id_digest,
            self.timestamp_seconds,
            &self.token_digest,
            &self.payload_digest,
        ));
        let expected_signature =
            sha256_digest(format!("mailgun-webhook-signature/v1|{expected_material}").as_bytes());
        if expected_material != self.signed_material_digest
            || expected_signature != self.signature_digest
        {
            return WebhookVerificationState::Tampered;
        }
        if now_seconds > self.timestamp_seconds
            && now_seconds - self.timestamp_seconds > MAX_WEBHOOK_AGE_SECONDS
        {
            WebhookVerificationState::Expired
        } else {
            WebhookVerificationState::Verified
        }
    }
}

impl Serialize for MailgunWebhookEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            &self.event_id_digest,
            self.timestamp_seconds,
            &self.token_digest,
            &self.payload_digest,
            &self.signed_material_digest,
            &self.signature_digest,
            &self.replay_key_digest,
        )
            .serialize(serializer)
    }
}

impl fmt::Debug for MailgunWebhookEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailgunWebhookEnvelope")
            .field("event_id_digest", &self.event_id_digest)
            .field("timestamp_seconds", &self.timestamp_seconds)
            .field("token_digest", &self.token_digest)
            .field("payload_digest", &self.payload_digest)
            .field("signature_digest", &self.signature_digest)
            .field("replay_key_digest", &self.replay_key_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunWebhookEvidence {
    pub state: WebhookVerificationState,
    pub envelope_digest: Digest,
    pub event_id_digest: Digest,
    pub payload_digest: Digest,
    pub signature_digest: Digest,
    pub replay_key_digest: Digest,
    pub verified: bool,
}

impl MailgunWebhookEvidence {
    pub fn from_envelope(envelope: &MailgunWebhookEnvelope, now_seconds: u64) -> Self {
        let state = envelope.verify(now_seconds);
        Self {
            state: state.clone(),
            envelope_digest: envelope.digest(),
            event_id_digest: envelope.event_id_digest.clone(),
            payload_digest: envelope.payload_digest.clone(),
            signature_digest: envelope.signature_digest.clone(),
            replay_key_digest: envelope.replay_key_digest.clone(),
            verified: matches!(state, WebhookVerificationState::Verified),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunDeliveryEvidence {
    pub state: EvidenceState,
    pub classification: EvidenceClassification,
    pub delivery_status: DeliveryStatus,
    pub events: Vec<MailgunDeliveryEvent>,
    pub suppression: Vec<SuppressionMetadata>,
    pub pages: u16,
    pub complete: bool,
    pub cursor_digest: Option<Digest>,
    pub request_receipts: Vec<MailgunRequestReceipt>,
    pub rate_limit: RateLimitReceipt,
    pub backoff: BackoffReceipt,
    pub webhook: Option<MailgunWebhookEvidence>,
    pub digests: MailgunEvidenceDigests,
    pub provenance: TransportProvenance,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub evidence_digest: Digest,
}

impl MailgunDeliveryEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "mailgun-delivery-evidence/v1",
            &self.state,
            &self.classification,
            &self.delivery_status,
            &self.events,
            &self.suppression,
            self.pages,
            self.complete,
            &self.cursor_digest,
            &self.request_receipts,
            &self.rate_limit,
            &self.backoff,
            &self.webhook,
            (
                &self.digests.plugin_version_digest,
                &self.digests.contract_digest,
                &self.digests.provider_digest,
                &self.digests.api_digest,
                &self.digests.scope_digest,
                &self.digests.revision_digest,
                &self.digests.consent_digest,
                &self.digests.registration_digest,
                &self.digests.events_digest,
                &self.digests.cursor_digest,
                &self.digests.webhook_digest,
            ),
            &self.provenance,
        ))
    }

    pub fn validate_integrity(&self) -> ModelResult<()> {
        if self.events.len() > MAX_TOTAL_EVENTS
            || self.request_receipts.len() > MAX_PAGES as usize
            || self.events.iter().any(|event| event.validate().is_err())
            || self.native
            || self.connected
            || self.first_party
            || self.provider_receipt
            || !self.proposal_only
            || self.digests.evidence_digest != self.evidence_digest
            || self.evidence_digest != self.digest()
        {
            return Err(ModelError::InvalidEvent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunRegistration {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl MailgunRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        api_digest: Digest,
        scope_digest: Digest,
        revision_digest: Digest,
        consent_digest: Digest,
        secret_reference_digest: Digest,
    ) -> ModelResult<Self> {
        for value in [
            &version_digest,
            &contract_digest,
            &provider_digest,
            &api_digest,
            &scope_digest,
            &revision_digest,
            &consent_digest,
            &secret_reference_digest,
        ] {
            if !valid_digest(value) {
                return Err(ModelError::InvalidDigest);
            }
        }
        let registration_revision = Revision::new(1)?;
        let mut registration = Self {
            version_digest,
            contract_digest,
            provider_digest,
            api_digest,
            scope_digest,
            revision_digest,
            consent_digest,
            secret_reference_digest,
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> ModelResult<RegistrationRevocationReceipt> {
        if !self.is_active() {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            state: self.state.clone(),
        })
    }

    pub fn restore(&mut self) -> ModelResult<()> {
        if self.is_active() {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "mailgun-registration/v1",
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            &self.state,
        ))
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.compute_digest() == self.registration_digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope("registration digest"))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunDeliveryResultProposal {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: MailgunDeliveryEvidence,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MailgunDeliveryResultProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> ModelResult<()> {
        if self.evidence.validate_integrity().is_err()
            || !self.review_only
            || self.native
            || self.connected
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != proposal_digest_for_service(self)
        {
            return Err(ModelError::InvalidScope("proposal integrity"));
        }
        Ok(())
    }
}

pub(crate) fn proposal_digest_for_service(proposal: &MailgunDeliveryResultProposal) -> Digest {
    canonical_digest(&(
        "mailgun-delivery-result-proposal/v1",
        &proposal.project,
        &proposal.mission,
        &proposal.work_product,
        &proposal.evidence.evidence_digest,
        &proposal.scope_digest,
        &proposal.revision_digest,
        &proposal.consent_digest,
        &proposal.registration_digest,
        proposal.review_only,
        proposal.native,
        proposal.connected,
        proposal.first_party,
        proposal.provider_receipt,
        proposal.outcome_adopted,
        proposal.work_product_adopted,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunDeliveryResultRecord {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub idempotency_digest: Digest,
    pub recorded_at_seconds: u64,
    pub replayed: bool,
    pub review_only: bool,
    pub native: bool,
    pub connected: bool,
    pub record_digest: Digest,
}

impl MailgunDeliveryResultRecord {
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.record_digest.clone()
    }

    pub fn validate_integrity(&self) -> ModelResult<()> {
        if !valid_digest(&self.idempotency_digest)
            || !self.review_only
            || self.native
            || self.connected
            || self.record_digest != record_digest(self)
        {
            return Err(ModelError::InvalidScope("record integrity"));
        }
        Ok(())
    }
}

pub(crate) fn record_digest(record: &MailgunDeliveryResultRecord) -> Digest {
    canonical_digest(&(
        "mailgun-delivery-result-record/v1",
        &record.project,
        &record.mission,
        &record.work_product,
        &record.proposal_digest,
        &record.evidence_digest,
        &record.scope_digest,
        &record.revision_digest,
        &record.registration_digest,
        &record.idempotency_digest,
        record.recorded_at_seconds,
        record.replayed,
        record.review_only,
        record.native,
        record.connected,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationFailure {
    pub code: String,
    pub detail_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub checked_registration_digest: Digest,
    pub failure: Option<VerificationFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdempotencyKeyReceipt {
    pub idempotency_digest: Digest,
    pub replayed: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct IdempotencyKey {
    digest: Digest,
}

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let raw = value.into();
        if !valid_text(&raw, MAX_IDENTIFIER_BYTES, false) {
            return Err(ModelError::InvalidIdempotencyKey);
        }
        let digest = sha256_digest(format!("mailgun-idempotency/v1|{raw}").as_bytes());
        Ok(Self { digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("digest", &self.digest)
            .finish()
    }
}

#[allow(dead_code)]
fn _bounds_are_bound() -> (usize, usize, usize) {
    (MAX_EVENTS_PER_PAGE, MAX_RESPONSE_BYTES, MAX_TAG_BYTES)
}
