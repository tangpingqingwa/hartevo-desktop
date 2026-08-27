use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsMarketplaceEntitlementError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES};

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
            Err(AwsMarketplaceEntitlementError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsMarketplaceEntitlementError::InvalidDigest)
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
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_product_code(value: &str) -> bool {
    valid_text(value, 255, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_arn(value: &str) -> bool {
    valid_text(value, 2_048, false) && value.starts_with("arn:")
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProductCode(String);

impl ProductCode {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_product_code(&value) {
            Ok(Self(value))
        } else {
            Err(AwsMarketplaceEntitlementError::InvalidIdentifier {
                field: "product-code",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-product-code/v1",
            &[("value", self.0.clone())],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_product_code(&self.0) {
            Ok(())
        } else {
            Err(AwsMarketplaceEntitlementError::InvalidIdentifier {
                field: "product-code",
            })
        }
    }
}

impl Serialize for ProductCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl fmt::Debug for ProductCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductCode")
            .field("value", &self.0)
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomerReferenceKind {
    AwsAccountId,
    CustomerIdentifier,
}

/// A customer reference stores only its kind and digest. The input identifier
/// is zeroized after hashing and has no accessor.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustomerReference {
    kind: CustomerReferenceKind,
    digest: Digest,
}

impl CustomerReference {
    pub fn new(kind: CustomerReferenceKind, value: impl Into<String>) -> Result<Self> {
        let mut value = value.into();
        let valid = match kind {
            CustomerReferenceKind::AwsAccountId => {
                value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
            }
            CustomerReferenceKind::CustomerIdentifier => valid_text(&value, 255, true),
        };
        if !valid {
            value.zeroize();
            return Err(AwsMarketplaceEntitlementError::InvalidIdentifier {
                field: "customer-reference",
            });
        }
        let digest = Digest::from_parts(
            "aws-marketplace-customer-reference/v1",
            &[("kind", format!("{kind:?}")), ("value", value.clone())],
        );
        value.zeroize();
        Ok(Self { kind, digest })
    }

    pub fn aws_account(value: impl Into<String>) -> Result<Self> {
        Self::new(CustomerReferenceKind::AwsAccountId, value)
    }

    pub fn customer_identifier(value: impl Into<String>) -> Result<Self> {
        Self::new(CustomerReferenceKind::CustomerIdentifier, value)
    }

    pub const fn kind(&self) -> CustomerReferenceKind {
        self.kind
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn redacted(&self) -> String {
        format!("customer:{}", &self.digest.as_str()[..16])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.digest.validate()
    }
}

impl Serialize for CustomerReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CustomerReference", 2)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("digest", &self.digest)?;
        state.end()
    }
}

impl fmt::Debug for CustomerReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomerReference")
            .field("kind", &self.kind)
            .field("digest", &self.digest)
            .finish()
    }
}

/// A dimension is retained only as a digest because AWS returns it as an
/// opaque entitlement string.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntitlementDimension {
    digest: Digest,
}

impl EntitlementDimension {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let mut value = value.into();
        if !valid_text(&value, 255, true) {
            value.zeroize();
            return Err(AwsMarketplaceEntitlementError::InvalidIdentifier { field: "dimension" });
        }
        let digest = Digest::from_parts(
            "aws-marketplace-entitlement-dimension/v1",
            &[("value", value.clone())],
        );
        value.zeroize();
        Ok(Self { digest })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn redacted(&self) -> String {
        format!("dimension:{}", &self.digest.as_str()[..16])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.digest.validate()
    }
}

impl fmt::Debug for EntitlementDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntitlementDimension")
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LicenseReference {
    digest: Digest,
}

impl LicenseReference {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let mut value = value.into();
        if !valid_arn(&value) {
            value.zeroize();
            return Err(AwsMarketplaceEntitlementError::InvalidIdentifier {
                field: "license-arn",
            });
        }
        let digest = Digest::from_parts(
            "aws-marketplace-license-arn/v1",
            &[("value", value.clone())],
        );
        value.zeroize();
        Ok(Self { digest })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn redacted(&self) -> String {
        format!("license:{}", &self.digest.as_str()[..16])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.digest.validate()
    }
}

impl fmt::Debug for LicenseReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LicenseReference")
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryStatus {
    Valid,
    Expired,
    OutsideRequiredWindow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryWindow {
    observed_at: DateTime<Utc>,
    required_until: DateTime<Utc>,
}

impl ExpiryWindow {
    pub fn new(observed_at: DateTime<Utc>, required_until: DateTime<Utc>) -> Result<Self> {
        if required_until < observed_at {
            return Err(AwsMarketplaceEntitlementError::InvalidScope);
        }
        Ok(Self {
            observed_at,
            required_until,
        })
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn required_until(&self) -> DateTime<Utc> {
        self.required_until
    }

    pub fn classify(&self, expires_at: DateTime<Utc>) -> ExpiryStatus {
        if expires_at <= self.observed_at {
            ExpiryStatus::Expired
        } else if expires_at < self.required_until {
            ExpiryStatus::OutsideRequiredWindow
        } else {
            ExpiryStatus::Valid
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-expiry-window/v1",
            &[
                ("observed_at", self.observed_at.to_rfc3339()),
                ("required_until", self.required_until.to_rfc3339()),
            ],
        )
    }
}

macro_rules! revisioned_identity {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsMarketplaceEntitlementError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn id_digest(&self) -> Digest {
                Digest::from_parts(concat!($domain, "-id/v1"), &[("id", self.id.clone())])
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!($domain, "/v1"),
                    &[
                        ("id", self.id_digest().as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AwsMarketplaceEntitlementError::InvalidScope)
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("id", &self.id)?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &self.id_digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

revisioned_identity!(MissionIdentity, "aws-marketplace-mission");
revisioned_identity!(ProjectIdentity, "aws-marketplace-project");
revisioned_identity!(WorkProductIdentity, "aws-marketplace-work-product");

#[derive(Clone, Eq, PartialEq)]
pub struct AwsMarketplaceEntitlementScope {
    product: ProductCode,
    customer: CustomerReference,
    dimension: EntitlementDimension,
    license: LicenseReference,
    expiry: ExpiryWindow,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsMarketplaceEntitlementScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        product: ProductCode,
        customer: CustomerReference,
        dimension: EntitlementDimension,
        license: LicenseReference,
        expiry: ExpiryWindow,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            product,
            customer,
            dimension,
            license,
            expiry,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn product(&self) -> &ProductCode {
        &self.product
    }

    pub fn customer(&self) -> &CustomerReference {
        &self.customer
    }

    pub fn dimension(&self) -> &EntitlementDimension {
        &self.dimension
    }

    pub fn license(&self) -> &LicenseReference {
        &self.license
    }

    pub fn expiry(&self) -> &ExpiryWindow {
        &self.expiry
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-entitlement-scope/v1",
            &[
                ("product", self.product.digest().as_str().to_owned()),
                ("customer", self.customer.digest().as_str().to_owned()),
                ("dimension", self.dimension.digest().as_str().to_owned()),
                ("license", self.license.digest().as_str().to_owned()),
                ("expiry", self.expiry.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.product.validate()?;
        self.customer.validate()?;
        self.dimension.validate()?;
        self.license.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl Serialize for AwsMarketplaceEntitlementScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsMarketplaceEntitlementScope", 9)?;
        state.serialize_field("productCode", &self.product)?;
        state.serialize_field("customer", &self.customer)?;
        state.serialize_field("dimensionDigest", self.dimension.digest())?;
        state.serialize_field("licenseDigest", self.license.digest())?;
        state.serialize_field("expiry", &self.expiry)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.end()
    }
}

impl fmt::Debug for AwsMarketplaceEntitlementScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsMarketplaceEntitlementScope")
            .field("digest", &self.digest())
            .field("product", &self.product)
            .field("customer", &self.customer)
            .field("dimension", &self.dimension)
            .field("license", &self.license)
            .field("expiry", &self.expiry)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomerFilter {
    CustomerAwsAccountId(Digest),
    CustomerIdentifier(Digest),
}

impl CustomerFilter {
    pub fn from_reference(reference: &CustomerReference) -> Self {
        match reference.kind() {
            CustomerReferenceKind::AwsAccountId => {
                Self::CustomerAwsAccountId(reference.digest().clone())
            }
            CustomerReferenceKind::CustomerIdentifier => {
                Self::CustomerIdentifier(reference.digest().clone())
            }
        }
    }

    pub fn digest(&self) -> &Digest {
        match self {
            Self::CustomerAwsAccountId(digest) | Self::CustomerIdentifier(digest) => digest,
        }
    }

    pub const fn kind(&self) -> CustomerReferenceKind {
        match self {
            Self::CustomerAwsAccountId(_) => CustomerReferenceKind::AwsAccountId,
            Self::CustomerIdentifier(_) => CustomerReferenceKind::CustomerIdentifier,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.digest().validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEntitlementsFilter {
    product_code: ProductCode,
    customer: CustomerFilter,
    dimension_digest: Digest,
    license_digest: Digest,
}

impl GetEntitlementsFilter {
    pub fn new(
        product_code: ProductCode,
        customer: CustomerFilter,
        dimension: &EntitlementDimension,
        license: &LicenseReference,
    ) -> Result<Self> {
        let filter = Self {
            product_code,
            customer,
            dimension_digest: dimension.digest().clone(),
            license_digest: license.digest().clone(),
        };
        filter.validate()?;
        Ok(filter)
    }

    pub fn for_scope(scope: &AwsMarketplaceEntitlementScope) -> Result<Self> {
        Self::new(
            scope.product().clone(),
            CustomerFilter::from_reference(scope.customer()),
            scope.dimension(),
            scope.license(),
        )
    }

    pub fn product_code(&self) -> &ProductCode {
        &self.product_code
    }

    pub fn customer(&self) -> &CustomerFilter {
        &self.customer
    }

    pub fn dimension_digest(&self) -> &Digest {
        &self.dimension_digest
    }

    pub fn license_digest(&self) -> &Digest {
        &self.license_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-get-entitlements-filter/v1",
            &[
                ("product", self.product_code.digest().as_str().to_owned()),
                ("customer_kind", format!("{:?}", self.customer.kind())),
                ("customer", self.customer.digest().as_str().to_owned()),
                ("dimension", self.dimension_digest.as_str().to_owned()),
                ("license", self.license_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsMarketplaceEntitlementScope) -> Result<()> {
        self.validate()?;
        if self.product_code != *scope.product()
            || self.customer.digest() != scope.customer().digest()
            || self.customer.kind() != scope.customer().kind()
            || self.dimension_digest != *scope.dimension().digest()
            || self.license_digest != *scope.license().digest()
        {
            return Err(AwsMarketplaceEntitlementError::FilterMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        self.product_code.validate()?;
        self.customer.validate()?;
        self.dimension_digest.validate()?;
        self.license_digest.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PageTokenReference {
    digest: Digest,
}

impl PageTokenReference {
    pub fn from_raw(value: impl Into<String>) -> Result<Self> {
        let mut value = value.into();
        if !valid_text(&value, 4_096, false) {
            value.zeroize();
            return Err(AwsMarketplaceEntitlementError::InvalidRequest);
        }
        let digest =
            Digest::from_parts("aws-marketplace-next-token/v1", &[("value", value.clone())]);
        value.zeroize();
        Ok(Self { digest })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.digest.validate()
    }
}

impl Serialize for PageTokenReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.digest.serialize(serializer)
    }
}

impl fmt::Debug for PageTokenReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageTokenReference")
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The caller-supplied handle is hashed and dropped;
/// it is never serializable, displayable, or present in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsMarketplaceEntitlementError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-marketplace-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-marketplace-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsMarketplaceEntitlementScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-marketplace-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
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

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &AwsMarketplaceEntitlementScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsMarketplaceEntitlementError::InvalidSecretReference);
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
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
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
            "aws-marketplace-entitlement-permissions/v1",
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
            Err(AwsMarketplaceEntitlementError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
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
        let consent = Self {
            id: id.into(),
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
            "aws-marketplace-entitlement-consent/v1",
            &[
                ("id", self.id.clone()),
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
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(AwsMarketplaceEntitlementError::InvalidConsent);
        }
        Ok(())
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("revision", &self.revision)
            .field("permissions", &self.permissions)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for ConsentScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConsentScope", 5)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("permissions", &self.permissions)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementProjection {
    pub product_code: ProductCode,
    pub customer_reference_digest: Digest,
    pub dimension_digest: Digest,
    pub license_arn_digest: Digest,
    pub expiration_date: DateTime<Utc>,
    pub entitlement_value_digest: Digest,
}

impl EntitlementProjection {
    pub fn for_scope(
        scope: &AwsMarketplaceEntitlementScope,
        expiration_date: DateTime<Utc>,
        entitlement_value_digest: Digest,
    ) -> Self {
        Self {
            product_code: scope.product().clone(),
            customer_reference_digest: scope.customer().digest().clone(),
            dimension_digest: scope.dimension().digest().clone(),
            license_arn_digest: scope.license().digest().clone(),
            expiration_date,
            entitlement_value_digest,
        }
    }

    /// Normalize an AWS response without retaining customer, license,
    /// dimension, or raw entitlement-value strings.
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw(
        scope: &AwsMarketplaceEntitlementScope,
        customer_kind: CustomerReferenceKind,
        customer_value: impl Into<String>,
        dimension_value: impl Into<String>,
        license_arn: impl Into<String>,
        expiration_date: DateTime<Utc>,
        entitlement_value: impl Into<String>,
    ) -> Result<Self> {
        let customer = CustomerReference::new(customer_kind, customer_value)?;
        let dimension = EntitlementDimension::new(dimension_value)?;
        let license = LicenseReference::new(license_arn)?;
        let mut value = entitlement_value.into();
        if !valid_text(&value, 4_096, true) {
            value.zeroize();
            return Err(AwsMarketplaceEntitlementError::InvalidText {
                field: "entitlement-value",
            });
        }
        let value_digest = Digest::from_parts(
            "aws-marketplace-entitlement-value/v1",
            &[("value", value.clone())],
        );
        value.zeroize();
        let projection = Self {
            product_code: scope.product().clone(),
            customer_reference_digest: customer.digest().clone(),
            dimension_digest: dimension.digest().clone(),
            license_arn_digest: license.digest().clone(),
            expiration_date,
            entitlement_value_digest: value_digest,
        };
        projection.validate_integrity()?;
        Ok(projection)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-entitlement-projection/v1",
            &[
                ("product", self.product_code.digest().as_str().to_owned()),
                (
                    "customer",
                    self.customer_reference_digest.as_str().to_owned(),
                ),
                ("dimension", self.dimension_digest.as_str().to_owned()),
                ("license", self.license_arn_digest.as_str().to_owned()),
                ("expiration", self.expiration_date.to_rfc3339()),
                ("value", self.entitlement_value_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsMarketplaceEntitlementScope) -> Result<()> {
        self.validate_integrity()?;
        if self.product_code != *scope.product()
            || self.customer_reference_digest != *scope.customer().digest()
            || self.dimension_digest != *scope.dimension().digest()
            || self.license_arn_digest != *scope.license().digest()
        {
            return Err(AwsMarketplaceEntitlementError::FilterMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        self.product_code.validate()?;
        self.customer_reference_digest.validate()?;
        self.dimension_digest.validate()?;
        self.license_arn_digest.validate()?;
        self.entitlement_value_digest.validate()?;
        if self.expiration_date.timestamp() < 0 {
            return Err(AwsMarketplaceEntitlementError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryProjection {
    pub observed_at: DateTime<Utc>,
    pub required_until: DateTime<Utc>,
    pub total: usize,
    pub valid: usize,
    pub expired: usize,
    pub outside_required_window: usize,
    pub earliest_expiration: Option<DateTime<Utc>>,
}

impl ExpiryProjection {
    pub fn from_entitlements(
        window: &ExpiryWindow,
        entitlements: &[EntitlementProjection],
    ) -> Self {
        let mut valid = 0;
        let mut expired = 0;
        let mut outside_required_window = 0;
        let mut earliest_expiration: Option<DateTime<Utc>> = None;
        for entitlement in entitlements {
            earliest_expiration = Some(
                earliest_expiration.map_or(entitlement.expiration_date, |current| {
                    current.min(entitlement.expiration_date)
                }),
            );
            match window.classify(entitlement.expiration_date) {
                ExpiryStatus::Valid => valid += 1,
                ExpiryStatus::Expired => expired += 1,
                ExpiryStatus::OutsideRequiredWindow => outside_required_window += 1,
            }
        }
        Self {
            observed_at: window.observed_at(),
            required_until: window.required_until(),
            total: entitlements.len(),
            valid,
            expired,
            outside_required_window,
            earliest_expiration,
        }
    }

    pub const fn is_fully_valid(&self) -> bool {
        self.total > 0 && self.valid == self.total
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-expiry-projection/v1",
            &[
                ("observed_at", self.observed_at.to_rfc3339()),
                ("required_until", self.required_until.to_rfc3339()),
                ("total", self.total.to_string()),
                ("valid", self.valid.to_string()),
                ("expired", self.expired.to_string()),
                (
                    "outside_required_window",
                    self.outside_required_window.to_string(),
                ),
                (
                    "earliest_expiration",
                    self.earliest_expiration
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementEvidenceState {
    Complete,
    Empty,
    EmptyPage,
    Expired,
    FilterMismatch,
    PaginationLoop,
    PageLimitExceeded,
    AccessLoss,
    Throttled,
    NotFound,
    Partial,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
    RegistrationReversed,
    ConsentExpired,
    ConsentRevoked,
}

impl EntitlementEvidenceState {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
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

pub fn mission_projection(identity: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

pub fn project_projection(identity: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

pub fn work_product_projection(identity: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub registration_digest: Digest,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub pages_digest: Option<Digest>,
    pub expiry_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        self.registration_digest.validate()?;
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.api_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.scope_digest.validate()?;
        self.filter_digest.validate()?;
        self.request_digest.validate()?;
        self.pages_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.expiry_digest.validate()?;
        self.evidence_digest.validate()
    }
}
