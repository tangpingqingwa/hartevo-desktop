//! Digest-only Entity Resolution scope and evidence models.

use std::{collections::BTreeMap, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsEntityResolutionError, Result};
use crate::{MAX_FIELD_BYTES, MAX_IDENTIFIER_BYTES, MAX_RECORD_FIELDS, MAX_RESPONSE_BYTES};

/// A lowercase SHA-256 digest used as the only retained representation of
/// source-record values, provider identifiers, and provider result material.
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
            Err(AwsEntityResolutionError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsEntityResolutionError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
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

fn valid_arn(value: &str) -> bool {
    valid_text(value, 2_048, false) && value.starts_with("arn:")
}

/// Bounded provider resource name. Its raw value is used only for constructing
/// provider paths and is never serialized or emitted by Debug.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceName(String);

impl ResourceName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value, MAX_IDENTIFIER_BYTES) {
            Ok(Self(value))
        } else {
            Err(AwsEntityResolutionError::InvalidIdentifier {
                field: "resource-name",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-entity-resolution-resource-name/v1",
            &[("value", self.0.clone())],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0, MAX_IDENTIFIER_BYTES) {
            Ok(())
        } else {
            Err(AwsEntityResolutionError::InvalidIdentifier {
                field: "resource-name",
            })
        }
    }
}

impl fmt::Debug for ResourceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceName")
            .field(&format!("resource:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

/// AWS account identifier with a redacted Debug/serialization surface.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(AwsEntityResolutionError::InvalidIdentifier { field: "account" })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-entity-resolution-account/v1",
            &[("account", self.0.clone())],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.0.len() == 12 && self.0.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(())
        } else {
            Err(AwsEntityResolutionError::InvalidIdentifier { field: "account" })
        }
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&format!("account:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

/// AWS region identifier with a redacted Debug/serialization surface.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value, 64) {
            Ok(Self(value))
        } else {
            Err(AwsEntityResolutionError::InvalidIdentifier { field: "region" })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-entity-resolution-region/v1",
            &[("region", self.0.clone())],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0, 64) {
            Ok(())
        } else {
            Err(AwsEntityResolutionError::InvalidIdentifier { field: "region" })
        }
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsRegion")
            .field(&format!("region:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

/// A schema, namespace, or workflow resource identity. Resource names are
/// bounded provider metadata; ARNs are immediately reduced to digests.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceIdentity {
    name: ResourceName,
    arn_digest: Option<Digest>,
}

impl ResourceIdentity {
    pub fn new(name: ResourceName, arn: Option<impl Into<String>>) -> Result<Self> {
        let arn_digest = arn
            .map(Into::into)
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-entity-resolution-resource-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsEntityResolutionError::InvalidIdentifier {
                        field: "resource-arn",
                    })
                }
            })
            .transpose()?;
        Ok(Self { name, arn_digest })
    }

    pub fn name(&self) -> &ResourceName {
        &self.name
    }

    pub fn arn_digest(&self) -> Option<&Digest> {
        self.arn_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-entity-resolution-resource/v1",
            &[
                ("name", self.name.digest().as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.name.validate()?;
        self.arn_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for ResourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for ResourceIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ResourceIdentity", 2)?;
        state.serialize_field("nameDigest", &self.name.digest())?;
        state.serialize_field("arnDigest", &self.arn_digest)?;
        state.end()
    }
}

pub type SchemaMappingIdentity = ResourceIdentity;
pub type IdNamespaceIdentity = ResourceIdentity;
pub type MatchingWorkflowIdentity = ResourceIdentity;

macro_rules! governance_identity {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id_digest: Digest,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let mut id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    id.zeroize();
                    return Err(AwsEntityResolutionError::InvalidScope);
                }
                let id_digest = Digest::from_parts(
                    concat!("aws-entity-resolution-", $domain, "-id/v1"),
                    &[("id", id.clone())],
                );
                id.zeroize();
                Ok(Self {
                    id_digest,
                    revision,
                })
            }

            pub fn id_digest(&self) -> &Digest {
                &self.id_digest
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-entity-resolution-", $domain, "/v1"),
                    &[
                        ("id", self.id_digest.as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if self.revision == 0 {
                    return Err(AwsEntityResolutionError::InvalidScope);
                }
                self.id_digest.validate()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &self.id_digest)
                    .field("revision", &self.revision)
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("idDigest", &self.id_digest)?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }
    };
}

governance_identity!(ProjectScope, "project");
governance_identity!(MissionScope, "mission");
governance_identity!(WorkProductScope, "work-product");

pub type ProjectIdentity = ProjectScope;
pub type MissionIdentity = MissionScope;
pub type WorkProductIdentity = WorkProductScope;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchemaAttributeType {
    Name,
    EmailAddress,
    PhoneNumber,
    Address,
    DateOfBirth,
    UniqueId,
    Other,
}

impl SchemaAttributeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "NAME",
            Self::EmailAddress => "EMAIL_ADDRESS",
            Self::PhoneNumber => "PHONE_NUMBER",
            Self::Address => "ADDRESS",
            Self::DateOfBirth => "DATE_OF_BIRTH",
            Self::UniqueId => "UNIQUE_ID",
            Self::Other => "OTHER",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaAttributeMetadata {
    pub attribute_name_digest: Digest,
    pub attribute_type: SchemaAttributeType,
    pub required: bool,
    pub normalization_enabled: bool,
    pub attribute_digest: Digest,
}

impl SchemaAttributeMetadata {
    pub fn from_field(
        field_name: impl AsRef<str>,
        attribute_type: SchemaAttributeType,
        required: bool,
        normalization_enabled: bool,
    ) -> Result<Self> {
        let field_name = field_name.as_ref();
        if !valid_text(field_name, MAX_FIELD_BYTES, false) {
            return Err(AwsEntityResolutionError::InvalidIdentifier {
                field: "schema-field",
            });
        }
        let attribute_name_digest = Digest::from_parts(
            "aws-entity-resolution-schema-field/v1",
            &[("name", field_name.to_owned())],
        );
        let attribute_digest = Digest::from_parts(
            "aws-entity-resolution-schema-attribute/v1",
            &[
                ("name", attribute_name_digest.as_str().to_owned()),
                ("type", attribute_type.as_str().to_owned()),
                ("required", required.to_string()),
                ("normalized", normalization_enabled.to_string()),
            ],
        );
        Ok(Self {
            attribute_name_digest,
            attribute_type,
            required,
            normalization_enabled,
            attribute_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.attribute_name_digest.validate()?;
        if self.attribute_digest
            != Digest::from_parts(
                "aws-entity-resolution-schema-attribute/v1",
                &[
                    ("name", self.attribute_name_digest.as_str().to_owned()),
                    ("type", self.attribute_type.as_str().to_owned()),
                    ("required", self.required.to_string()),
                    ("normalized", self.normalization_enabled.to_string()),
                ],
            )
        {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MatchingType {
    RuleBased,
    MachineLearning,
    ProviderServices,
}

impl MatchingType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuleBased => "RULE_BASED",
            Self::MachineLearning => "MACHINE_LEARNING",
            Self::ProviderServices => "PROVIDER_SERVICES",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaMappingMetadata {
    pub name_digest: Digest,
    pub arn_digest: Option<Digest>,
    pub attribute_count: u16,
    pub attribute_digests: Vec<Digest>,
    pub attribute_type_counts: BTreeMap<String, u16>,
    pub primary_key_present: bool,
    pub normalization_enabled: bool,
    pub created_at_epoch_seconds: Option<i64>,
    pub updated_at_epoch_seconds: Option<i64>,
    pub metadata_digest: Digest,
}

impl SchemaMappingMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl AsRef<str>,
        arn: Option<impl AsRef<str>>,
        attributes: &[SchemaAttributeMetadata],
        primary_key_present: bool,
        normalization_enabled: bool,
        created_at_epoch_seconds: Option<i64>,
        updated_at_epoch_seconds: Option<i64>,
    ) -> Result<Self> {
        let name = ResourceName::new(name.as_ref().to_owned())?;
        let arn_digest = arn
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-entity-resolution-schema-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsEntityResolutionError::InvalidIdentifier {
                        field: "schema-mapping-arn",
                    })
                }
            })
            .transpose()?;
        if attributes.is_empty() || attributes.len() > 128 {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        for attribute in attributes {
            attribute.validate()?;
        }
        let mut attribute_type_counts = BTreeMap::new();
        for attribute in attributes {
            *attribute_type_counts
                .entry(attribute.attribute_type.as_str().to_owned())
                .or_insert(0) += 1;
        }
        let name_digest = name.digest();
        let metadata_digest = Digest::from_parts(
            "aws-entity-resolution-schema-mapping/v1",
            &[
                ("name", name_digest.as_str().to_owned()),
                (
                    "arn",
                    arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("attribute_count", attributes.len().to_string()),
                (
                    "attribute_digests",
                    attributes
                        .iter()
                        .map(|attribute| attribute.attribute_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("primary_key", primary_key_present.to_string()),
                ("normalized", normalization_enabled.to_string()),
                (
                    "created",
                    created_at_epoch_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "updated",
                    updated_at_epoch_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Ok(Self {
            name_digest,
            arn_digest,
            attribute_count: u16::try_from(attributes.len())
                .map_err(|_| AwsEntityResolutionError::InvalidMetadata)?,
            attribute_digests: attributes
                .iter()
                .map(|attribute| attribute.attribute_digest.clone())
                .collect(),
            attribute_type_counts,
            primary_key_present,
            normalization_enabled,
            created_at_epoch_seconds,
            updated_at_epoch_seconds,
            metadata_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.name_digest.validate()?;
        self.arn_digest.as_ref().map(Digest::validate).transpose()?;
        if self.attribute_count == 0
            || self.attribute_digests.len() != usize::from(self.attribute_count)
            || self.attribute_type_counts.values().sum::<u16>() != self.attribute_count
        {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        for digest in &self.attribute_digests {
            digest.validate()?;
        }
        let expected = Digest::from_parts(
            "aws-entity-resolution-schema-mapping/v1",
            &[
                ("name", self.name_digest.as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("attribute_count", self.attribute_count.to_string()),
                (
                    "attribute_digests",
                    self.attribute_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("primary_key", self.primary_key_present.to_string()),
                ("normalized", self.normalization_enabled.to_string()),
                (
                    "created",
                    self.created_at_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "updated",
                    self.updated_at_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        if expected != self.metadata_digest {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchingWorkflowMetadata {
    pub name_digest: Digest,
    pub arn_digest: Option<Digest>,
    pub matching_type: MatchingType,
    pub schema_mapping_digest: Digest,
    pub id_namespace_digest: Option<Digest>,
    pub source_count: u16,
    pub normalization_enabled: bool,
    pub rule_count: u16,
    pub created_at_epoch_seconds: Option<i64>,
    pub updated_at_epoch_seconds: Option<i64>,
    pub metadata_digest: Digest,
}

impl MatchingWorkflowMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl AsRef<str>,
        arn: Option<impl AsRef<str>>,
        matching_type: MatchingType,
        schema_mapping_digest: Digest,
        id_namespace_digest: Option<Digest>,
        source_count: u16,
        normalization_enabled: bool,
        rule_count: u16,
        created_at_epoch_seconds: Option<i64>,
        updated_at_epoch_seconds: Option<i64>,
    ) -> Result<Self> {
        let name = ResourceName::new(name.as_ref().to_owned())?;
        if source_count == 0 || rule_count == 0 {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        schema_mapping_digest.validate()?;
        if let Some(digest) = &id_namespace_digest {
            digest.validate()?;
        }
        let arn_digest = arn
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-entity-resolution-workflow-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsEntityResolutionError::InvalidIdentifier {
                        field: "matching-workflow-arn",
                    })
                }
            })
            .transpose()?;
        let name_digest = name.digest();
        let metadata_digest = Digest::from_parts(
            "aws-entity-resolution-matching-workflow/v1",
            &[
                ("name", name_digest.as_str().to_owned()),
                (
                    "arn",
                    arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("matching_type", matching_type.as_str().to_owned()),
                ("schema", schema_mapping_digest.as_str().to_owned()),
                (
                    "namespace",
                    id_namespace_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("source_count", source_count.to_string()),
                ("normalized", normalization_enabled.to_string()),
                ("rule_count", rule_count.to_string()),
                (
                    "created",
                    created_at_epoch_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "updated",
                    updated_at_epoch_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Ok(Self {
            name_digest,
            arn_digest,
            matching_type,
            schema_mapping_digest,
            id_namespace_digest,
            source_count,
            normalization_enabled,
            rule_count,
            created_at_epoch_seconds,
            updated_at_epoch_seconds,
            metadata_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.name_digest.validate()?;
        self.arn_digest.as_ref().map(Digest::validate).transpose()?;
        self.schema_mapping_digest.validate()?;
        self.id_namespace_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if self.source_count == 0 || self.rule_count == 0 {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        let expected = Digest::from_parts(
            "aws-entity-resolution-matching-workflow/v1",
            &[
                ("name", self.name_digest.as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("matching_type", self.matching_type.as_str().to_owned()),
                ("schema", self.schema_mapping_digest.as_str().to_owned()),
                (
                    "namespace",
                    self.id_namespace_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("source_count", self.source_count.to_string()),
                ("normalized", self.normalization_enabled.to_string()),
                ("rule_count", self.rule_count.to_string()),
                (
                    "created",
                    self.created_at_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "updated",
                    self.updated_at_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        if expected != self.metadata_digest {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdNamespaceType {
    Source,
    Target,
}

impl IdNamespaceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "SOURCE",
            Self::Target => "TARGET",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdNamespaceMetadata {
    pub name_digest: Digest,
    pub arn_digest: Option<Digest>,
    pub namespace_type: IdNamespaceType,
    pub description_digest: Option<Digest>,
    pub id_mapping_type_digests: Vec<Digest>,
    pub created_at_epoch_seconds: Option<i64>,
    pub updated_at_epoch_seconds: Option<i64>,
    pub metadata_digest: Digest,
}

impl IdNamespaceMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl AsRef<str>,
        arn: Option<impl AsRef<str>>,
        namespace_type: IdNamespaceType,
        description: Option<impl AsRef<str>>,
        id_mapping_types: &[impl AsRef<str>],
        created_at_epoch_seconds: Option<i64>,
        updated_at_epoch_seconds: Option<i64>,
    ) -> Result<Self> {
        let name = ResourceName::new(name.as_ref().to_owned())?;
        if id_mapping_types.len() > 16 {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        let description_digest = description
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_parts(
                        "aws-entity-resolution-namespace-description/v1",
                        &[("description", value)],
                    ))
                } else {
                    Err(AwsEntityResolutionError::InvalidMetadata)
                }
            })
            .transpose()?;
        let arn_digest = arn
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-entity-resolution-namespace-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsEntityResolutionError::InvalidIdentifier {
                        field: "id-namespace-arn",
                    })
                }
            })
            .transpose()?;
        let mut id_mapping_type_digests = Vec::with_capacity(id_mapping_types.len());
        for mapping_type in id_mapping_types {
            let mapping_type = mapping_type.as_ref();
            if !valid_identifier(mapping_type, 64) {
                return Err(AwsEntityResolutionError::InvalidMetadata);
            }
            id_mapping_type_digests.push(Digest::from_parts(
                "aws-entity-resolution-id-mapping-type/v1",
                &[("type", mapping_type.to_owned())],
            ));
        }
        let name_digest = name.digest();
        let metadata_digest = Digest::from_parts(
            "aws-entity-resolution-id-namespace/v1",
            &[
                ("name", name_digest.as_str().to_owned()),
                (
                    "arn",
                    arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("type", namespace_type.as_str().to_owned()),
                (
                    "description",
                    description_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "mapping_types",
                    id_mapping_type_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "created",
                    created_at_epoch_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "updated",
                    updated_at_epoch_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Ok(Self {
            name_digest,
            arn_digest,
            namespace_type,
            description_digest,
            id_mapping_type_digests,
            created_at_epoch_seconds,
            updated_at_epoch_seconds,
            metadata_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.name_digest.validate()?;
        self.arn_digest.as_ref().map(Digest::validate).transpose()?;
        self.description_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if self.id_mapping_type_digests.len() > 16 {
            return Err(AwsEntityResolutionError::InvalidMetadata);
        }
        for digest in &self.id_mapping_type_digests {
            digest.validate()?;
        }
        let expected = Digest::from_parts(
            "aws-entity-resolution-id-namespace/v1",
            &[
                ("name", self.name_digest.as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("type", self.namespace_type.as_str().to_owned()),
                (
                    "description",
                    self.description_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "mapping_types",
                    self.id_mapping_type_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "created",
                    self.created_at_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "updated",
                    self.updated_at_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        if expected != self.metadata_digest {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }
}

/// A bounded, deterministic fingerprint of a source record. The input map is
/// not retained; only the digest and the normalization mode survive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRecordFingerprint {
    pub field_count: u16,
    pub apply_normalization: bool,
    pub normalized_record_digest: Digest,
    pub fingerprint_digest: Digest,
}

impl SourceRecordFingerprint {
    pub fn from_record(
        record: &BTreeMap<String, String>,
        apply_normalization: bool,
    ) -> Result<Self> {
        if record.is_empty() || record.len() > MAX_RECORD_FIELDS {
            return Err(AwsEntityResolutionError::InvalidRecord);
        }
        let mut bytes = Vec::new();
        for (key, value) in record {
            if !valid_record_component(key, apply_normalization)
                || !valid_record_component(value, apply_normalization)
            {
                return Err(AwsEntityResolutionError::InvalidRecord);
            }
            let key = normalize_component(key, apply_normalization);
            let value = normalize_component(value, apply_normalization);
            append_field(&mut bytes, &key);
            append_field(&mut bytes, &value);
        }
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(AwsEntityResolutionError::InvalidRecord);
        }
        let normalized_record_digest = Digest::from_bytes(&bytes);
        let fingerprint_digest = Digest::from_parts(
            "aws-entity-resolution-source-record-fingerprint/v1",
            &[
                ("record", normalized_record_digest.as_str().to_owned()),
                ("field_count", record.len().to_string()),
                ("normalization", apply_normalization.to_string()),
            ],
        );
        Ok(Self {
            field_count: u16::try_from(record.len())
                .map_err(|_| AwsEntityResolutionError::InvalidRecord)?,
            apply_normalization,
            normalized_record_digest,
            fingerprint_digest,
        })
    }

    pub fn from_digest(
        field_count: u16,
        apply_normalization: bool,
        normalized_record_digest: Digest,
    ) -> Result<Self> {
        if field_count == 0 || usize::from(field_count) > MAX_RECORD_FIELDS {
            return Err(AwsEntityResolutionError::InvalidRecord);
        }
        normalized_record_digest.validate()?;
        let fingerprint_digest = Digest::from_parts(
            "aws-entity-resolution-source-record-fingerprint/v1",
            &[
                ("record", normalized_record_digest.as_str().to_owned()),
                ("field_count", field_count.to_string()),
                ("normalization", apply_normalization.to_string()),
            ],
        );
        Ok(Self {
            field_count,
            apply_normalization,
            normalized_record_digest,
            fingerprint_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.fingerprint_digest.clone()
    }

    pub fn fingerprint_digest(&self) -> &Digest {
        &self.fingerprint_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.field_count == 0 || usize::from(self.field_count) > MAX_RECORD_FIELDS {
            return Err(AwsEntityResolutionError::InvalidRecord);
        }
        self.normalized_record_digest.validate()?;
        let expected = Digest::from_parts(
            "aws-entity-resolution-source-record-fingerprint/v1",
            &[
                ("record", self.normalized_record_digest.as_str().to_owned()),
                ("field_count", self.field_count.to_string()),
                ("normalization", self.apply_normalization.to_string()),
            ],
        );
        if expected != self.fingerprint_digest {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }
}

fn normalize_component(value: &str, apply_normalization: bool) -> String {
    if !apply_normalization {
        return value.to_owned();
    }
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn valid_record_component(value: &str, _apply_normalization: bool) -> bool {
    !value.is_empty() && value.len() <= MAX_FIELD_BYTES && !value.chars().any(char::is_control)
}

/// Exact account/region/resource/source-record/Project/Mission/Work Product
/// binding for one Entity Resolution read proposal.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsEntityResolutionScope {
    account: AwsAccountId,
    region: AwsRegion,
    schema_mapping: SchemaMappingIdentity,
    id_namespace: IdNamespaceIdentity,
    matching_workflow: MatchingWorkflowIdentity,
    source_record_fingerprint: SourceRecordFingerprint,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
}

impl AwsEntityResolutionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        schema_mapping: SchemaMappingIdentity,
        id_namespace: IdNamespaceIdentity,
        matching_workflow: MatchingWorkflowIdentity,
        source_record_fingerprint: SourceRecordFingerprint,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            schema_mapping,
            id_namespace,
            matching_workflow,
            source_record_fingerprint,
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

    pub fn schema_mapping(&self) -> &SchemaMappingIdentity {
        &self.schema_mapping
    }

    pub fn id_namespace(&self) -> &IdNamespaceIdentity {
        &self.id_namespace
    }

    pub fn matching_workflow(&self) -> &MatchingWorkflowIdentity {
        &self.matching_workflow
    }

    pub fn source_record_fingerprint(&self) -> &SourceRecordFingerprint {
        &self.source_record_fingerprint
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-entity-resolution-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("schema", self.schema_mapping.digest().as_str().to_owned()),
                ("namespace", self.id_namespace.digest().as_str().to_owned()),
                (
                    "workflow",
                    self.matching_workflow.digest().as_str().to_owned(),
                ),
                (
                    "record",
                    self.source_record_fingerprint.digest().as_str().to_owned(),
                ),
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
        self.schema_mapping.validate()?;
        self.id_namespace.validate()?;
        self.matching_workflow.validate()?;
        self.source_record_fingerprint.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsEntityResolutionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEntityResolutionScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("schema_mapping", &self.schema_mapping)
            .field("id_namespace", &self.id_namespace)
            .field("matching_workflow", &self.matching_workflow)
            .field("source_record_fingerprint", &self.source_record_fingerprint)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .finish()
    }
}

pub type AwsEntityResolutionResultScope = AwsEntityResolutionScope;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The supplied handle is hashed and zeroized before
/// return. The type deliberately has no Serialize or Deserialize implementation.
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
            return Err(AwsEntityResolutionError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-entity-resolution-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-entity-resolution-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsEntityResolutionScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-entity-resolution-opaque-sigv4-reference/v1",
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

    pub(crate) fn validate(&self, scope: &AwsEntityResolutionScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsEntityResolutionError::InvalidSecretReference);
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MatchStatus {
    Matched,
    Unmatched,
    Ambiguous,
    Invalid,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl MatchStatus {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Matched | Self::Unmatched | Self::Ambiguous | Self::Invalid | Self::Revoked
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: Vec<String>,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(permissions: Vec<String>, revision: u64) -> Result<Self> {
        if revision == 0 || permissions.is_empty() || permissions.len() > 32 {
            return Err(AwsEntityResolutionError::InvalidPermissionSnapshot);
        }
        let mut permissions = permissions;
        permissions.sort();
        permissions.dedup();
        if permissions.iter().any(|permission| {
            !valid_text(permission, MAX_IDENTIFIER_BYTES, false)
                || permission.contains("Create")
                || permission.contains("Update")
                || permission.contains("Delete")
                || permission.contains("Start")
                || permission == "s3:GetObject"
                || permission == "kms:Decrypt"
                || permission == "iam:PassRole"
                || permission == "outcome.adopt"
                || permission == "work_product.adopt"
        }) {
            return Err(AwsEntityResolutionError::InvalidPermissionSnapshot);
        }
        let permission_digest = Digest::from_parts(
            "aws-entity-resolution-permission-snapshot/v1",
            &[
                ("revision", revision.to_string()),
                ("permissions", permissions.join(",")),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            permission_digest,
        })
    }

    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(
            crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            revision,
        )
    }

    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0 || self.permissions.is_empty() {
            return Err(AwsEntityResolutionError::InvalidPermissionSnapshot);
        }
        let mut expected = self.permissions.clone();
        expected.sort();
        expected.dedup();
        if expected != self.permissions {
            return Err(AwsEntityResolutionError::InvalidPermissionSnapshot);
        }
        let expected_digest = Digest::from_parts(
            "aws-entity-resolution-permission-snapshot/v1",
            &[
                ("revision", self.revision.to_string()),
                ("permissions", self.permissions.join(",")),
            ],
        );
        if expected_digest != self.permission_digest {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub namespace_digest: Option<Digest>,
    pub workflow_digest: Option<Digest>,
    pub schema_digest: Option<Digest>,
    pub source_record_fingerprint_digest: Digest,
    pub request_digest: Digest,
    pub match_group_digest: Option<Digest>,
    pub match_rule_digest: Option<Digest>,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.namespace_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.workflow_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.schema_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.source_record_fingerprint_digest.validate()?;
        self.request_digest.validate()?;
        self.match_group_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.match_rule_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.result_digest.validate()?;
        self.evidence_digest.validate()
    }
}
