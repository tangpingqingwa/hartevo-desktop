use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION, SERVICE_ID,
    error::{PaddleSubscriptionResultError, Result},
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TEXT_BYTES: usize = 256;
pub const MAX_CURRENCY_BYTES: usize = 3;
pub const MAX_TRANSACTION_PAGE_LIMIT: u32 = 30;
pub const MAX_EVENT_PAGE_LIMIT: u32 = 200;
pub const MAX_PAGES: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_EVENTS_PER_PAGE: usize = 200;
pub const MAX_TRANSACTIONS_PER_PAGE: usize = 30;
pub const MAX_PAYMENT_ATTEMPTS: usize = 32;

/// Lowercase SHA-256 used for identity, scope, response, redaction, and
/// evidence fences. The digest is serializable; the material it represents is
/// not retained in Layer 1.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    #[must_use]
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Paddle contract values serialize");
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn pending() -> Self {
        Self::from_text("pending-paddle-subscription-result-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self, field: &'static str) -> Result<()> {
        if self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(())
        } else {
            Err(PaddleSubscriptionResultError::InvalidDigest { field })
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > MAX_IDENTIFIER_BYTES
                    || value.chars().any(char::is_control)
                    || value.chars().any(char::is_whitespace)
                    || value
                        .bytes()
                        .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'%' | b'&' | b'='))
                {
                    Err(PaddleSubscriptionResultError::InvalidIdentifier { field: $field })
                } else {
                    Ok(Self(value))
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_identifier!(AccountId, "account_id");
bounded_identifier!(SubscriptionId, "subscription_id");
bounded_identifier!(TransactionId, "transaction_id");
bounded_identifier!(EventId, "event_id");
bounded_identifier!(HartevoProjectId, "hartevo_project_id");
bounded_identifier!(MissionId, "mission_id");
bounded_identifier!(WorkProductId, "work_product_id");

pub type PaddleAccountId = AccountId;
pub type PaddleSubscriptionId = SubscriptionId;
pub type PaddleTransactionId = TransactionId;
pub type PaddleEventId = EventId;

/// A non-floating revision fence. It is deliberately numeric so a caller
/// cannot hide an unbounded provider label in a registration digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(PaddleSubscriptionResultError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact external API host/version binding. Loopback is admitted only for a
/// local evidence seam and does not change the native/connected claim.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiBinding {
    pub base_url: String,
    pub api_version: String,
    pub revision: Revision,
}

impl ApiBinding {
    pub fn new(
        base_url: impl Into<String>,
        api_version: impl Into<String>,
        revision: Revision,
    ) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let api_version = api_version.into();
        let official = base_url == crate::OFFICIAL_PADDLE_HOST;
        let loopback =
            base_url.starts_with("http://127.0.0.1:") || base_url.starts_with("http://localhost:");
        if (!official && !loopback)
            || base_url.contains('?')
            || base_url.contains('#')
            || base_url.contains("..")
            || base_url.chars().any(char::is_whitespace)
            || base_url.len() > MAX_IDENTIFIER_BYTES
            || api_version != crate::PADDLE_API_VERSION
        {
            return Err(PaddleSubscriptionResultError::InvalidApiBinding);
        }
        Revision::new(revision.get())?;
        Ok(Self {
            base_url,
            api_version,
            revision,
        })
    }

    #[must_use]
    pub fn official(revision: Revision) -> Self {
        Self {
            base_url: String::from(crate::OFFICIAL_PADDLE_HOST),
            api_version: String::from(crate::PADDLE_API_VERSION),
            revision,
        }
    }

    #[must_use]
    pub fn loopback(revision: Revision) -> Self {
        Self {
            base_url: String::from("http://127.0.0.1:8787"),
            api_version: String::from(crate::PADDLE_API_VERSION),
            revision,
        }
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.base_url.clone(),
            self.api_version.clone(),
            self.revision,
        )
        .map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&self.revision)
    }
}

pub type PaddleApiBinding = ApiBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaddlePermission {
    SubscriptionRead,
    TransactionRead,
    NotificationRead,
}

impl PaddlePermission {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubscriptionRead => "subscription.read",
            Self::TransactionRead => "transaction.read",
            Self::NotificationRead => "notification.read",
        }
    }
}

/// The exact read-only permission lease. No write permission can be
/// represented by this type.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionBinding {
    pub permissions: Vec<PaddlePermission>,
    pub revision: Revision,
    pub digest: Digest,
}

impl PermissionBinding {
    #[must_use]
    pub fn read_only(revision: Revision) -> Self {
        let mut binding = Self {
            permissions: vec![
                PaddlePermission::SubscriptionRead,
                PaddlePermission::TransactionRead,
                PaddlePermission::NotificationRead,
            ],
            revision,
            digest: Digest::pending(),
        };
        binding.digest = binding.computed_digest();
        binding
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.permissions, self.revision))
    }

    pub fn validate(&self) -> Result<()> {
        Revision::new(self.revision.get())?;
        let expected = vec![
            PaddlePermission::SubscriptionRead,
            PaddlePermission::TransactionRead,
            PaddlePermission::NotificationRead,
        ];
        if self.permissions != expected || self.digest != self.computed_digest() {
            return Err(PaddleSubscriptionResultError::InvalidPermission);
        }
        Ok(())
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&self.revision)
    }
}

pub type PaddlePermissionBinding = PermissionBinding;

/// Opaque API-key reference. It intentionally has no Serialize or
/// Deserialize implementation and never stores caller-supplied key bytes.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.revision == other.revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    pub fn api_key(
        opaque_reference: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.is_empty()
            || opaque_reference.len() > MAX_IDENTIFIER_BYTES
            || opaque_reference.chars().any(char::is_control)
            || opaque_reference.chars().any(char::is_whitespace)
        {
            return Err(PaddleSubscriptionResultError::InvalidIdentifier {
                field: "opaque_api_key_reference",
            });
        }
        scope_digest.validate("secret_scope_digest")?;
        Revision::new(revision.get())?;
        let reference_digest = Digest::from_serializable(&(
            "paddle-api-key-secret-reference/v1",
            opaque_reference,
            &scope_digest,
            revision,
        ));
        Ok(Self {
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self> {
        Self::api_key(opaque_reference, scope_digest, revision)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate("secret_reference_digest")?;
        self.scope_digest.validate("secret_scope_digest")?;
        Revision::new(self.revision.get())?;
        Ok(())
    }

    pub fn validate_for_scope(&self, scope_digest: &Digest) -> Result<()> {
        self.validate()?;
        if &self.scope_digest != scope_digest {
            return Err(PaddleSubscriptionResultError::SecretReferenceMismatch);
        }
        if self.revoked {
            return Err(PaddleSubscriptionResultError::SecretRevoked);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(PaddleSubscriptionResultError::SecretRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(PaddleSubscriptionResultError::InvalidRequest(
                "secret is active",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventEntity {
    Subscription,
    Transaction,
}

impl EventEntity {
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Subscription => "subscription.",
            Self::Transaction => "transaction.",
        }
    }
}

/// The exact external account/subscription and Hartevo Mission binding used
/// by this plugin. A transaction id, when present, narrows the read further.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleBillingScopeIdentity {
    pub account_id: AccountId,
    pub subscription_id: SubscriptionId,
    pub transaction_id: Option<TransactionId>,
    pub event_entities: Vec<EventEntity>,
    pub api: ApiBinding,
    pub permission: PermissionBinding,
    pub hartevo_project_id: HartevoProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub scope_revision: Revision,
}

impl PaddleBillingScopeIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        subscription_id: SubscriptionId,
        transaction_id: Option<TransactionId>,
        api: ApiBinding,
        permission: PermissionBinding,
        hartevo_project_id: HartevoProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        project_revision: Revision,
        mission_revision: Revision,
        work_product_revision: Revision,
        scope_revision: Revision,
    ) -> Result<Self> {
        let identity = Self {
            account_id,
            subscription_id,
            transaction_id,
            event_entities: vec![EventEntity::Subscription, EventEntity::Transaction],
            api,
            permission,
            hartevo_project_id,
            mission_id,
            work_product_id,
            project_revision,
            mission_revision,
            work_product_revision,
            scope_revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.subscription_id.validate()?;
        if let Some(transaction) = &self.transaction_id {
            transaction.validate()?;
        }
        if self.event_entities != [EventEntity::Subscription, EventEntity::Transaction] {
            return Err(PaddleSubscriptionResultError::InvalidScope(
                "event_entities",
            ));
        }
        self.api.validate()?;
        self.permission.validate()?;
        self.hartevo_project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        for (field, revision) in [
            ("project_revision", self.project_revision),
            ("mission_revision", self.mission_revision),
            ("work_product_revision", self.work_product_revision),
            ("scope_revision", self.scope_revision),
        ] {
            Revision::new(revision.get())
                .map_err(|_| PaddleSubscriptionResultError::InvalidRevision { field })?;
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.project_revision,
            self.mission_revision,
            self.work_product_revision,
            self.scope_revision,
        ))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PaddleBillingScope {
    identity: PaddleBillingScopeIdentity,
    secret_reference: SecretReference,
}

impl fmt::Debug for PaddleBillingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaddleBillingScope")
            .field("identity", &self.identity)
            .field("secret_reference", &self.secret_reference)
            .finish()
    }
}

impl PaddleBillingScope {
    pub fn new(
        identity: PaddleBillingScopeIdentity,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        identity.validate()?;
        let scope_digest = identity.digest();
        secret_reference.validate_for_scope(&scope_digest)?;
        Ok(Self {
            identity,
            secret_reference,
        })
    }

    pub fn fixture() -> Result<Self> {
        let identity = PaddleBillingScopeIdentity::new(
            AccountId::new("acct_fixture")?,
            SubscriptionId::new("sub_fixture")?,
            None,
            ApiBinding::official(Revision::new(1)?),
            PermissionBinding::read_only(Revision::new(1)?),
            HartevoProjectId::new("project_fixture")?,
            MissionId::new("mission_fixture")?,
            WorkProductId::new("work_product_fixture")?,
            Revision::new(1)?,
            Revision::new(1)?,
            Revision::new(1)?,
            Revision::new(1)?,
        )?;
        let secret = SecretReference::api_key(
            "fixture-api-key-reference",
            identity.digest(),
            Revision::new(1)?,
        )?;
        Self::new(identity, secret)
    }

    #[must_use]
    pub fn identity(&self) -> &PaddleBillingScopeIdentity {
        &self.identity
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.identity.digest()
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        self.identity.revision_digest()
    }

    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        self.secret_reference
            .validate_for_scope(&self.identity.digest())
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.secret_reference.revoke()
    }

    pub fn restore_secret(&mut self) -> Result<()> {
        self.secret_reference.restore()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleBillingRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub implementation_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision_digest: Digest,
    pub registration_revision: Revision,
    pub status: RegistrationStatus,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

impl PaddleBillingRegistration {
    pub fn new(
        scope: &PaddleBillingScope,
        provider_digest: Digest,
        provider_version: impl Into<String>,
        contract_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        provider_digest.validate("provider_digest")?;
        contract_digest.validate("contract_digest")?;
        let mut registration = Self {
            plugin_id: String::from(PLUGIN_ID),
            plugin_version: String::from(PLUGIN_VERSION),
            contract_version: String::from(CONTRACT_VERSION),
            contract_digest,
            implementation_digest: Digest::from_text(concat!(
                "hartevo-paddle-subscription-result-plugin/",
                env!("CARGO_PKG_VERSION")
            )),
            service_id: String::from(SERVICE_ID),
            provider_id: String::from(PROVIDER_ID),
            provider_version: provider_version.into(),
            provider_digest,
            api_digest: scope.identity.api.digest(),
            permission_digest: scope.identity.permission.digest.clone(),
            scope_digest: scope.scope_digest(),
            secret_reference_digest: scope.secret_reference().reference_digest().clone(),
            revision_digest: scope.revision_digest(),
            registration_revision: scope.identity.scope_revision,
            status: RegistrationStatus::Active,
            reversible: true,
            revocable: true,
            registration_digest: Digest::pending(),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate_for(scope, &registration.provider_digest.clone())?;
        Ok(registration)
    }

    fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.registration_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn validate(&self) -> Result<()> {
        for (field, digest) in [
            ("contract_digest", &self.contract_digest),
            ("implementation_digest", &self.implementation_digest),
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("secret_reference_digest", &self.secret_reference_digest),
            ("revision_digest", &self.revision_digest),
            ("registration_digest", &self.registration_digest),
        ] {
            digest.validate(field)?;
        }
        Revision::new(self.registration_revision.get())?;
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.implementation_digest
                != Digest::from_text(concat!(
                    "hartevo-paddle-subscription-result-plugin/",
                    env!("CARGO_PKG_VERSION")
                ))
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.status != RegistrationStatus::Active
                && self.status != RegistrationStatus::Revoked
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.computed_digest()
        {
            return Err(PaddleSubscriptionResultError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn validate_for(&self, scope: &PaddleBillingScope, provider_digest: &Digest) -> Result<()> {
        self.validate()?;
        scope.validate()?;
        if self.provider_digest != *provider_digest {
            return Err(PaddleSubscriptionResultError::ProviderDrift);
        }
        if self.api_digest != scope.identity.api.digest() {
            return Err(PaddleSubscriptionResultError::ApiDrift);
        }
        if self.permission_digest != scope.identity.permission.digest {
            return Err(PaddleSubscriptionResultError::PermissionDrift);
        }
        if self.scope_digest != scope.scope_digest()
            || self.revision_digest != scope.revision_digest()
        {
            return Err(PaddleSubscriptionResultError::RevisionDrift);
        }
        if self.secret_reference_digest != scope.secret_reference().reference_digest().clone() {
            return Err(PaddleSubscriptionResultError::SecretReferenceMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation> {
        if self.status == RegistrationStatus::Revoked {
            return Err(PaddleSubscriptionResultError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            status: self.status,
        })
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.status == RegistrationStatus::Active {
            return Err(PaddleSubscriptionResultError::InvalidRequest(
                "registration is active",
            ));
        }
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.computed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub status: RegistrationStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Trialing,
    PastDue,
    Paused,
    Canceled,
    ProviderUnknown,
}

impl SubscriptionStatus {
    pub fn parse(value: &str) -> Self {
        match value {
            "active" => Self::Active,
            "trialing" => Self::Trialing,
            "past_due" => Self::PastDue,
            "paused" => Self::Paused,
            "canceled" | "cancelled" => Self::Canceled,
            _ => Self::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Trialing => "trialing",
            Self::PastDue => "past_due",
            Self::Paused => "paused",
            Self::Canceled => "canceled",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

pub type PaddleSubscriptionStatus = SubscriptionStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Draft,
    Ready,
    Billed,
    Paid,
    Completed,
    PastDue,
    Canceled,
    Refunded,
    Failed,
    ProviderUnknown,
}

impl TransactionStatus {
    pub fn parse(value: &str) -> Self {
        match value {
            "draft" => Self::Draft,
            "ready" => Self::Ready,
            "billed" => Self::Billed,
            "paid" => Self::Paid,
            "completed" => Self::Completed,
            "past_due" => Self::PastDue,
            "canceled" | "cancelled" => Self::Canceled,
            "refunded" => Self::Refunded,
            "failed" | "payment_failed" => Self::Failed,
            _ => Self::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Ready => "ready",
            Self::Billed => "billed",
            Self::Paid => "paid",
            Self::Completed => "completed",
            Self::PastDue => "past_due",
            Self::Canceled => "canceled",
            Self::Refunded => "refunded",
            Self::Failed => "failed",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

pub type PaddleTransactionStatus = TransactionStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentAttemptStatus {
    Created,
    Authorized,
    AuthorizedFlagged,
    PendingNoActionRequired,
    ActionRequired,
    Captured,
    Error,
    Canceled,
    Dropped,
    Unknown,
    ProviderUnknown,
}

impl PaymentAttemptStatus {
    pub fn parse(value: &str) -> Self {
        match value {
            "created" => Self::Created,
            "authorized" => Self::Authorized,
            "authorized_flagged" => Self::AuthorizedFlagged,
            "pending_no_action_required" => Self::PendingNoActionRequired,
            "action_required" => Self::ActionRequired,
            "captured" => Self::Captured,
            "error" => Self::Error,
            "canceled" | "cancelled" => Self::Canceled,
            "dropped" => Self::Dropped,
            "unknown" => Self::Unknown,
            _ => Self::ProviderUnknown,
        }
    }
}

pub type PaddlePaymentAttemptStatus = PaymentAttemptStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledChangeAction {
    Cancel,
    Pause,
    Resume,
    ProviderUnknown,
}

impl ScheduledChangeAction {
    pub fn parse(value: &str) -> Self {
        match value {
            "cancel" => Self::Cancel,
            "pause" => Self::Pause,
            "resume" => Self::Resume,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMode {
    Automatic,
    Manual,
    ProviderUnknown,
}

impl CollectionMode {
    pub fn parse(value: &str) -> Self {
        match value {
            "automatic" => Self::Automatic,
            "manual" => Self::Manual,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmountSummary {
    pub currency_code: String,
    pub amount: String,
}

impl AmountSummary {
    pub fn new(currency_code: impl Into<String>, amount: impl Into<String>) -> Result<Self> {
        let currency_code = currency_code.into();
        let amount = amount.into();
        if currency_code.len() != MAX_CURRENCY_BYTES
            || !currency_code.bytes().all(|byte| byte.is_ascii_uppercase())
            || amount.is_empty()
            || amount.len() > MAX_TEXT_BYTES
            || amount.chars().any(char::is_control)
            || amount.chars().any(char::is_whitespace)
            || !amount
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'.')
        {
            return Err(PaddleSubscriptionResultError::InvalidText {
                field: "amount_summary",
            });
        }
        Ok(Self {
            currency_code,
            amount,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.currency_code.clone(), self.amount.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BillingPeriod {
    pub starts_at: String,
    pub ends_at: String,
}

impl BillingPeriod {
    pub fn new(starts_at: impl Into<String>, ends_at: impl Into<String>) -> Result<Self> {
        let starts_at = starts_at.into();
        let ends_at = ends_at.into();
        validate_text(&starts_at, "billing_period_starts_at")?;
        validate_text(&ends_at, "billing_period_ends_at")?;
        Ok(Self { starts_at, ends_at })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.starts_at.clone(), self.ends_at.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScheduledChange {
    pub action: ScheduledChangeAction,
    pub effective_at: String,
    pub resume_at: Option<String>,
}

impl ScheduledChange {
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.effective_at, "scheduled_change_effective_at")?;
        if let Some(resume_at) = &self.resume_at {
            validate_text(resume_at, "scheduled_change_resume_at")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleSubscriptionSummary {
    pub account_id: AccountId,
    pub subscription_id: SubscriptionId,
    pub customer_digest: Option<Digest>,
    pub status: SubscriptionStatus,
    pub currency_code: String,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub first_billed_at: Option<String>,
    pub next_billed_at: Option<String>,
    pub paused_at: Option<String>,
    pub canceled_at: Option<String>,
    pub current_billing_period: Option<BillingPeriod>,
    pub scheduled_change: Option<ScheduledChange>,
    pub collection_mode: Option<CollectionMode>,
    pub billing_cycle_digest: Option<Digest>,
    pub amount: Option<AmountSummary>,
    pub item_count: u32,
    pub item_digest: Option<Digest>,
    pub metadata_digest: Option<Digest>,
    pub source_digest: Digest,
}

impl PaddleSubscriptionSummary {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.subscription_id.validate()?;
        validate_currency(&self.currency_code)?;
        validate_optional_text(self.created_at.as_ref(), "created_at")?;
        validate_optional_text(self.started_at.as_ref(), "started_at")?;
        validate_optional_text(self.first_billed_at.as_ref(), "first_billed_at")?;
        validate_optional_text(self.next_billed_at.as_ref(), "next_billed_at")?;
        validate_optional_text(self.paused_at.as_ref(), "paused_at")?;
        validate_optional_text(self.canceled_at.as_ref(), "canceled_at")?;
        if let Some(period) = &self.current_billing_period {
            period.validate()?;
        }
        if let Some(change) = &self.scheduled_change {
            change.validate()?;
        }
        if let Some(amount) = &self.amount {
            amount.validate()?;
        }
        validate_optional_digest(self.customer_digest.as_ref(), "customer_digest")?;
        validate_optional_digest(self.billing_cycle_digest.as_ref(), "billing_cycle_digest")?;
        validate_optional_digest(self.item_digest.as_ref(), "item_digest")?;
        validate_optional_digest(self.metadata_digest.as_ref(), "metadata_digest")?;
        self.source_digest.validate("subscription_source_digest")
    }

    #[must_use]
    pub fn is_renewing(&self) -> bool {
        self.next_billed_at.is_some()
            && matches!(
                self.status,
                SubscriptionStatus::Active | SubscriptionStatus::Trialing
            )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddlePaymentAttemptSummary {
    pub attempt_digest: Digest,
    pub status: PaymentAttemptStatus,
    pub amount: Option<AmountSummary>,
    pub created_at: Option<String>,
    pub error_digest: Option<Digest>,
}

impl PaddlePaymentAttemptSummary {
    pub fn validate(&self) -> Result<()> {
        self.attempt_digest.validate("payment_attempt_digest")?;
        if let Some(amount) = &self.amount {
            amount.validate()?;
        }
        validate_optional_text(self.created_at.as_ref(), "payment_attempt_created_at")?;
        validate_optional_digest(self.error_digest.as_ref(), "payment_error_digest")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleTransactionSummary {
    pub account_id: AccountId,
    pub transaction_id: TransactionId,
    pub subscription_id: Option<SubscriptionId>,
    pub customer_digest: Option<Digest>,
    pub status: TransactionStatus,
    pub origin: Option<String>,
    pub currency_code: String,
    pub subtotal: Option<AmountSummary>,
    pub discount: Option<AmountSummary>,
    pub tax: Option<AmountSummary>,
    pub total: Option<AmountSummary>,
    pub earnings: Option<AmountSummary>,
    pub billing_period: Option<BillingPeriod>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub billed_at: Option<String>,
    pub completed_at: Option<String>,
    pub payment_attempts: Vec<PaddlePaymentAttemptSummary>,
    pub item_count: u32,
    pub item_digest: Option<Digest>,
    pub metadata_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub source_digest: Digest,
}

impl PaddleTransactionSummary {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.transaction_id.validate()?;
        if let Some(subscription) = &self.subscription_id {
            subscription.validate()?;
        }
        validate_currency(&self.currency_code)?;
        validate_optional_text(self.origin.as_ref(), "transaction_origin")?;
        for amount in [
            &self.subtotal,
            &self.discount,
            &self.tax,
            &self.total,
            &self.earnings,
        ]
        .into_iter()
        .flatten()
        {
            amount.validate()?;
        }
        if let Some(period) = &self.billing_period {
            period.validate()?;
        }
        for value in [
            &self.created_at,
            &self.updated_at,
            &self.billed_at,
            &self.completed_at,
        ] {
            validate_optional_text(value.as_ref(), "transaction_timestamp")?;
        }
        if self.payment_attempts.len() > MAX_PAYMENT_ATTEMPTS {
            return Err(PaddleSubscriptionResultError::InvalidResponse(
                "payment attempt bound",
            ));
        }
        for payment in &self.payment_attempts {
            payment.validate()?;
        }
        validate_optional_digest(self.customer_digest.as_ref(), "transaction_customer_digest")?;
        validate_optional_digest(self.item_digest.as_ref(), "transaction_item_digest")?;
        validate_optional_digest(self.metadata_digest.as_ref(), "transaction_metadata_digest")?;
        validate_optional_digest(self.error_digest.as_ref(), "transaction_error_digest")?;
        self.source_digest.validate("transaction_source_digest")
    }

    #[must_use]
    pub fn is_renewal(&self) -> bool {
        self.origin.as_deref() == Some("subscription_recurring")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleEventSummary {
    pub account_id: AccountId,
    pub event_id: EventId,
    pub event_type: String,
    pub subscription_id: Option<SubscriptionId>,
    pub transaction_id: Option<TransactionId>,
    pub subscription_status: Option<SubscriptionStatus>,
    pub transaction_status: Option<TransactionStatus>,
    pub occurred_at: String,
    pub customer_digest: Option<Digest>,
    pub item_digest: Option<Digest>,
    pub data_digest: Digest,
}

impl PaddleEventSummary {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.event_id.validate()?;
        validate_event_type(&self.event_type)?;
        if let Some(subscription) = &self.subscription_id {
            subscription.validate()?;
        }
        if let Some(transaction) = &self.transaction_id {
            transaction.validate()?;
        }
        validate_text(&self.occurred_at, "event_occurred_at")?;
        validate_optional_digest(self.customer_digest.as_ref(), "event_customer_digest")?;
        validate_optional_digest(self.item_digest.as_ref(), "event_item_digest")?;
        self.data_digest.validate("event_data_digest")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    Transactions,
    Events,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PaddleCursor {
    token: String,
    kind: CursorKind,
    scope_digest: Digest,
    previous_response_digest: Digest,
    issued_at: u64,
    expires_at: u64,
}

impl PaddleCursor {
    pub fn new(
        token: impl Into<String>,
        kind: CursorKind,
        scope_digest: Digest,
        previous_response_digest: Digest,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        let token = token.into();
        if token.is_empty()
            || token.len() > MAX_IDENTIFIER_BYTES
            || token.chars().any(char::is_control)
            || token.chars().any(char::is_whitespace)
            || token.bytes().any(|byte| matches!(byte, b'?' | b'#' | b'&'))
        {
            return Err(PaddleSubscriptionResultError::InvalidRequest("cursor"));
        }
        if expires_at <= issued_at || expires_at - issued_at > crate::EVENT_RETENTION_SECONDS {
            return Err(PaddleSubscriptionResultError::InvalidRequest(
                "cursor expiry",
            ));
        }
        scope_digest.validate("cursor_scope_digest")?;
        previous_response_digest.validate("cursor_response_digest")?;
        Ok(Self {
            token,
            kind,
            scope_digest,
            previous_response_digest,
            issued_at,
            expires_at,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub const fn kind(&self) -> CursorKind {
        self.kind
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.token,
            self.kind,
            &self.scope_digest,
            &self.previous_response_digest,
            self.issued_at,
            self.expires_at,
        ))
    }

    pub fn validate_for(&self, scope_digest: &Digest, kind: CursorKind, now: u64) -> Result<()> {
        if &self.scope_digest != scope_digest || self.kind != kind {
            return Err(PaddleSubscriptionResultError::CursorMismatch);
        }
        if now > self.expires_at {
            return Err(PaddleSubscriptionResultError::CursorExpired);
        }
        Ok(())
    }
}

impl fmt::Debug for PaddleCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaddleCursor")
            .field("cursor_digest", &self.digest())
            .field("kind", &self.kind)
            .field("scope_digest", &self.scope_digest)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

pub type PaddleTransactionCursor = PaddleCursor;
pub type PaddleEventCursor = PaddleCursor;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddleSubscriptionReadRequest {
    pub subscription_id: SubscriptionId,
    pub minimum_observed_at: u64,
}

impl PaddleSubscriptionReadRequest {
    pub fn new(subscription_id: SubscriptionId, minimum_observed_at: u64) -> Result<Self> {
        subscription_id.validate()?;
        Ok(Self {
            subscription_id,
            minimum_observed_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddleTransactionReadRequest {
    pub transaction_id: TransactionId,
    pub minimum_observed_at: u64,
}

impl PaddleTransactionReadRequest {
    pub fn new(transaction_id: TransactionId, minimum_observed_at: u64) -> Result<Self> {
        transaction_id.validate()?;
        Ok(Self {
            transaction_id,
            minimum_observed_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddleTransactionListRequest {
    pub subscription_id: SubscriptionId,
    pub limit: u32,
    pub cursor: Option<PaddleCursor>,
    pub minimum_observed_at: u64,
}

impl PaddleTransactionListRequest {
    pub fn new(
        subscription_id: SubscriptionId,
        limit: u32,
        cursor: Option<PaddleCursor>,
        minimum_observed_at: u64,
    ) -> Result<Self> {
        subscription_id.validate()?;
        if !(1..=MAX_TRANSACTION_PAGE_LIMIT).contains(&limit) {
            return Err(PaddleSubscriptionResultError::InvalidRequest(
                "transaction limit",
            ));
        }
        if cursor
            .as_ref()
            .is_some_and(|value| value.kind() != CursorKind::Transactions)
        {
            return Err(PaddleSubscriptionResultError::CursorMismatch);
        }
        Ok(Self {
            subscription_id,
            limit,
            cursor,
            minimum_observed_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddleEventListRequest {
    pub limit: u32,
    pub cursor: Option<PaddleCursor>,
    pub minimum_observed_at: u64,
}

impl PaddleEventListRequest {
    pub fn new(limit: u32, cursor: Option<PaddleCursor>, minimum_observed_at: u64) -> Result<Self> {
        if !(1..=MAX_EVENT_PAGE_LIMIT).contains(&limit) {
            return Err(PaddleSubscriptionResultError::InvalidRequest("event limit"));
        }
        if cursor
            .as_ref()
            .is_some_and(|value| value.kind() != CursorKind::Events)
        {
            return Err(PaddleSubscriptionResultError::CursorMismatch);
        }
        Ok(Self {
            limit,
            cursor,
            minimum_observed_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PaddleReadTarget {
    Subscription {
        subscription_id: SubscriptionId,
    },
    Transaction {
        transaction_id: TransactionId,
    },
    Transactions {
        subscription_id: SubscriptionId,
        limit: u32,
        cursor_digest: Option<Digest>,
    },
    Events {
        limit: u32,
        cursor_digest: Option<Digest>,
    },
}

pub type PaddleSubscriptionReadTarget = PaddleReadTarget;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    Empty,
    Present,
    Partial,
    AccessLost,
    ProviderUnknown,
    CursorExpired,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorProjection {
    pub class: String,
    pub status: Option<u16>,
    pub retryable: bool,
    pub response_digest: Option<Digest>,
}

impl ProviderErrorProjection {
    pub(crate) fn from_error(
        error: &crate::PaddleBillingProviderError,
        response_digest: Option<Digest>,
    ) -> Self {
        let class = match error {
            crate::PaddleBillingProviderError::BlockedEnv => "blocked_env",
            crate::PaddleBillingProviderError::Unauthorized => "unauthorized",
            crate::PaddleBillingProviderError::Forbidden => "forbidden",
            crate::PaddleBillingProviderError::NotFound => "not_found",
            crate::PaddleBillingProviderError::Conflict => "conflict",
            crate::PaddleBillingProviderError::RateLimited { .. } => "rate_limited",
            crate::PaddleBillingProviderError::Timeout => "timeout",
            crate::PaddleBillingProviderError::ServerError { .. } => "server_error",
            crate::PaddleBillingProviderError::TransportUnavailable => "transport_unavailable",
            crate::PaddleBillingProviderError::AccessLoss => "access_loss",
            crate::PaddleBillingProviderError::MalformedResponse(_) => "malformed_response",
            crate::PaddleBillingProviderError::PartialResponse => "partial_response",
            crate::PaddleBillingProviderError::ResponseTampered => "response_tampered",
            crate::PaddleBillingProviderError::UnexpectedStatus { .. } => "unexpected_status",
        }
        .to_owned();
        Self {
            class,
            status: error.status_code(),
            retryable: error.is_retryable(),
            response_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let retryable_class = matches!(
            self.class.as_str(),
            "rate_limited" | "timeout" | "server_error" | "transport_unavailable"
        );
        if !matches!(
            self.class.as_str(),
            "blocked_env"
                | "unauthorized"
                | "forbidden"
                | "not_found"
                | "conflict"
                | "rate_limited"
                | "timeout"
                | "server_error"
                | "transport_unavailable"
                | "access_loss"
                | "malformed_response"
                | "partial_response"
                | "response_tampered"
                | "unexpected_status"
        ) || self.class.len() > MAX_TEXT_BYTES
            || self.class.chars().any(char::is_control)
            || self.class.chars().any(char::is_whitespace)
            || self.retryable != retryable_class
            || self
                .status
                .is_some_and(|status| !(400..=599).contains(&status))
        {
            return Err(PaddleSubscriptionResultError::EvidenceTampered);
        }
        if let Some(response_digest) = &self.response_digest {
            response_digest.validate("provider_error_response_digest")?;
        }
        Ok(())
    }
}

/// Redacted evidence for a bounded subscription, transaction, or event read.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleBillingEvidence {
    pub target: PaddleReadTarget,
    pub subscription: Option<PaddleSubscriptionSummary>,
    pub transactions: Vec<PaddleTransactionSummary>,
    pub events: Vec<PaddleEventSummary>,
    pub next_cursor_digest: Option<Digest>,
    pub response_digest: Option<Digest>,
    pub page_count: u32,
    pub disposition: EvidenceDisposition,
    pub provider_error: Option<ProviderErrorProjection>,
    pub provenance: ProviderProvenance,
    pub observed_at: u64,
    pub snapshot_revision: Revision,
    pub registration_digest: Digest,
    pub implementation_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub payment_initiation: bool,
    pub durable_native_receipt: bool,
    pub independent_readback: bool,
    pub work_product_adopted: bool,
    pub kernel_authority: bool,
    pub evidence_digest: Digest,
}

impl PaddleBillingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        target: PaddleReadTarget,
        subscription: Option<PaddleSubscriptionSummary>,
        transactions: Vec<PaddleTransactionSummary>,
        events: Vec<PaddleEventSummary>,
        next_cursor_digest: Option<Digest>,
        response_digest: Option<Digest>,
        page_count: u32,
        disposition: EvidenceDisposition,
        provider_error: Option<ProviderErrorProjection>,
        provenance: ProviderProvenance,
        observed_at: u64,
        snapshot_revision: Revision,
        registration_digest: Digest,
        implementation_digest: Digest,
        provider_digest: Digest,
        api_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        revision_digest: Digest,
    ) -> Result<Self> {
        let mut evidence = Self {
            target,
            subscription,
            transactions,
            events,
            next_cursor_digest,
            response_digest,
            page_count,
            disposition,
            provider_error,
            provenance,
            observed_at,
            snapshot_revision,
            registration_digest,
            implementation_digest,
            provider_digest,
            api_digest,
            permission_digest,
            scope_digest,
            revision_digest,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            payment_initiation: false,
            durable_native_receipt: false,
            independent_readback: false,
            work_product_adopted: false,
            kernel_authority: false,
            evidence_digest: Digest::pending(),
        };
        evidence.validate_without_digest()?;
        evidence.evidence_digest = evidence.computed_digest();
        Ok(evidence)
    }

    fn validate_without_digest(&self) -> Result<()> {
        if self.page_count == 0
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.payment_initiation
            || self.durable_native_receipt
            || self.independent_readback
            || self.work_product_adopted
            || self.kernel_authority
        {
            return Err(PaddleSubscriptionResultError::EvidenceTampered);
        }
        Revision::new(self.snapshot_revision.get()).map_err(|_| {
            PaddleSubscriptionResultError::InvalidRevision {
                field: "snapshot_revision",
            }
        })?;
        for (field, digest) in [
            ("registration_digest", &self.registration_digest),
            ("implementation_digest", &self.implementation_digest),
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("revision_digest", &self.revision_digest),
        ] {
            digest.validate(field)?;
        }
        if let Some(cursor) = &self.next_cursor_digest {
            cursor.validate("next_cursor_digest")?;
        }
        if let Some(response) = &self.response_digest {
            response.validate("response_digest")?;
        }
        if let Some(provider_error) = &self.provider_error {
            provider_error.validate()?;
        }
        if let Some(subscription) = &self.subscription {
            subscription.validate()?;
        }
        if self.transactions.len() > MAX_TRANSACTIONS_PER_PAGE * MAX_PAGES {
            return Err(PaddleSubscriptionResultError::InvalidResponse(
                "transaction evidence bound",
            ));
        }
        for transaction in &self.transactions {
            transaction.validate()?;
        }
        if self.events.len() > MAX_EVENTS_PER_PAGE * MAX_PAGES {
            return Err(PaddleSubscriptionResultError::InvalidResponse(
                "event evidence bound",
            ));
        }
        for event in &self.events {
            event.validate()?;
        }
        if self.disposition == EvidenceDisposition::Present
            && self.subscription.is_none()
            && self.transactions.is_empty()
            && self.events.is_empty()
        {
            return Err(PaddleSubscriptionResultError::EvidenceTampered);
        }
        Ok(())
    }

    #[must_use]
    fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_without_digest()?;
        if self.evidence_digest != self.computed_digest() {
            return Err(PaddleSubscriptionResultError::EvidenceTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn has_renewal_evidence(&self) -> bool {
        self.subscription
            .as_ref()
            .is_some_and(PaddleSubscriptionSummary::is_renewing)
            || self
                .transactions
                .iter()
                .any(PaddleTransactionSummary::is_renewal)
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        Err(PaddleSubscriptionResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validate_optional_text(value: Option<&String>, field: &'static str) -> Result<()> {
    if let Some(value) = value {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_currency(value: &str) -> Result<()> {
    if value.len() != MAX_CURRENCY_BYTES || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Err(PaddleSubscriptionResultError::InvalidText {
            field: "currency_code",
        })
    } else {
        Ok(())
    }
}

fn validate_optional_digest(value: Option<&Digest>, field: &'static str) -> Result<()> {
    if let Some(value) = value {
        value.validate(field)?;
    }
    Ok(())
}

pub(crate) fn validate_event_type(value: &str) -> Result<()> {
    if value.len() > MAX_TEXT_BYTES
        || value.is_empty()
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || !(value.starts_with("subscription.") || value.starts_with("transaction."))
    {
        Err(PaddleSubscriptionResultError::InvalidText {
            field: "event_type",
        })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_event_scope(
    event: &PaddleEventSummary,
    scope: &PaddleBillingScope,
) -> Result<()> {
    event.validate()?;
    if event.account_id != scope.identity.account_id {
        return Err(PaddleSubscriptionResultError::AccountMismatch);
    }
    let matches_subscription =
        event.subscription_id.as_ref() == Some(&scope.identity.subscription_id);
    let matches_transaction = scope
        .identity
        .transaction_id
        .as_ref()
        .is_some_and(|id| event.transaction_id.as_ref() == Some(id));
    if !matches_subscription && !matches_transaction {
        return Err(PaddleSubscriptionResultError::EventMismatch);
    }
    Ok(())
}

pub(crate) fn validate_transaction_scope(
    transaction: &PaddleTransactionSummary,
    scope: &PaddleBillingScope,
) -> Result<()> {
    transaction.validate()?;
    if transaction.account_id != scope.identity.account_id {
        return Err(PaddleSubscriptionResultError::AccountMismatch);
    }
    if transaction.subscription_id.as_ref() != Some(&scope.identity.subscription_id) {
        return Err(PaddleSubscriptionResultError::SubscriptionMismatch);
    }
    if let Some(expected) = &scope.identity.transaction_id
        && transaction.transaction_id != *expected
    {
        return Err(PaddleSubscriptionResultError::TransactionMismatch);
    }
    Ok(())
}

pub(crate) fn validate_subscription_scope(
    subscription: &PaddleSubscriptionSummary,
    scope: &PaddleBillingScope,
) -> Result<()> {
    subscription.validate()?;
    if subscription.account_id != scope.identity.account_id {
        return Err(PaddleSubscriptionResultError::AccountMismatch);
    }
    if subscription.subscription_id != scope.identity.subscription_id {
        return Err(PaddleSubscriptionResultError::SubscriptionMismatch);
    }
    Ok(())
}
