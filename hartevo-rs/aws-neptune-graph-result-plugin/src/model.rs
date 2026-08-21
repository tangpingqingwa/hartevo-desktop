use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{LAYER1_PERMISSIONS, error::AwsNeptuneGraphResultError, error::Result};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 256;
pub(crate) const MAX_ENDPOINT_BYTES: usize = 512;
pub(crate) const MAX_PARAMETER_COUNT: usize = 8;
pub(crate) const MAX_PROJECTION_FIELDS: usize = 8;
pub(crate) const MAX_RESULT_ROWS: u32 = 512;
pub(crate) const MAX_RESULT_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_RESULT_TIME_MS: u64 = 30_000;
pub(crate) const MAX_RESULT_PAGES: u16 = 8;

/// A lowercase SHA-256 digest used as the public identity of sensitive or
/// otherwise bounded values.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    /// Digest arbitrary bytes immediately.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    /// Digest a public or secret value without retaining its source bytes.
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    /// Digest length-delimited fields under a stable domain separator.
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    /// Parse a digest from an external boundary.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsNeptuneGraphResultError::InvalidDigest)
        }
    }

    /// Borrow the hexadecimal digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsNeptuneGraphResultError::InvalidDigest)
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

fn valid_endpoint(value: &str) -> bool {
    valid_text(value, MAX_ENDPOINT_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'/' | b':'))
        && value.contains('.')
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsNeptuneGraphResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-neptune-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsNeptuneGraphResultError::InvalidIdentifier { field: $field })
                }
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

redacted_identifier!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_identifier!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
redacted_identifier!(VpcEndpoint, "vpc-endpoint", valid_endpoint);
redacted_identifier!(NeptuneClusterId, "cluster", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
redacted_identifier!(GraphNamespace, "graph", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));

macro_rules! revision_identity {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsNeptuneGraphResultError::InvalidIdentifier { field: $field });
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
                Digest::from_parts(
                    concat!("aws-neptune-", $field, "-id/v1"),
                    &[("id", self.id.clone())],
                )
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
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
                    Err(AwsNeptuneGraphResultError::InvalidIdentifier { field: $field })
                }
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

revision_identity!(MissionIdentity, "mission", "aws-neptune-mission/v1");
revision_identity!(ProjectIdentity, "project", "aws-neptune-project/v1");
revision_identity!(
    WorkProductIdentity,
    "work-product",
    "aws-neptune-work-product/v1"
);

/// The exact Mission, Project, and Work Product binding for one graph read.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsNeptuneGraphScope {
    account: AwsAccountId,
    region: AwsRegion,
    vpc_endpoint: VpcEndpoint,
    cluster: NeptuneClusterId,
    graph: GraphNamespace,
    query_template_digest: Digest,
    parameter_digest: Digest,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsNeptuneGraphScope {
    /// Construct and validate an exact account/endpoint/graph/query/Mission scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        vpc_endpoint: VpcEndpoint,
        cluster: NeptuneClusterId,
        graph: GraphNamespace,
        query_template_digest: Digest,
        parameter_digest: Digest,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            vpc_endpoint,
            cluster,
            graph,
            query_template_digest,
            parameter_digest,
            mission,
            project,
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

    pub fn vpc_endpoint(&self) -> &VpcEndpoint {
        &self.vpc_endpoint
    }

    pub fn cluster(&self) -> &NeptuneClusterId {
        &self.cluster
    }

    pub fn graph(&self) -> &GraphNamespace {
        &self.graph
    }

    pub fn query_template_digest(&self) -> &Digest {
        &self.query_template_digest
    }

    pub fn parameter_digest(&self) -> &Digest {
        &self.parameter_digest
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
            "aws-neptune-graph-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "vpc_endpoint",
                    self.vpc_endpoint.digest().as_str().to_owned(),
                ),
                ("cluster", self.cluster.digest().as_str().to_owned()),
                ("graph", self.graph.digest().as_str().to_owned()),
                (
                    "query_template",
                    self.query_template_digest.as_str().to_owned(),
                ),
                ("parameter", self.parameter_digest.as_str().to_owned()),
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
        self.account.validate()?;
        self.region.validate()?;
        self.vpc_endpoint.validate()?;
        self.cluster.validate()?;
        self.graph.validate()?;
        self.query_template_digest.validate()?;
        self.parameter_digest.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        Ok(())
    }
}

impl fmt::Debug for AwsNeptuneGraphScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsNeptuneGraphScope")
            .field("scope_digest", &self.digest())
            .field("account_digest", &self.account.digest())
            .field("region_digest", &self.region.digest())
            .field("vpc_endpoint_digest", &self.vpc_endpoint.digest())
            .field("cluster_digest", &self.cluster.digest())
            .field("graph_digest", &self.graph.digest())
            .field("query_template_digest", &self.query_template_digest)
            .field("parameter_digest", &self.parameter_digest)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl Serialize for AwsNeptuneGraphScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsNeptuneGraphScope", 10)?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("vpcEndpointDigest", &self.vpc_endpoint.digest())?;
        state.serialize_field("clusterDigest", &self.cluster.digest())?;
        state.serialize_field("graphDigest", &self.graph.digest())?;
        state.serialize_field("queryTemplateDigest", &self.query_template_digest)?;
        state.serialize_field("parameterDigest", &self.parameter_digest)?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.end()
    }
}

/// Least-privilege read permission metadata bound into registration.
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
            "aws-neptune-permissions/v1",
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
            Err(AwsNeptuneGraphResultError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

/// An opaque SigV4 credential handle.  The handle is never serializable and
/// its Debug implementation contains only digest metadata.
pub struct SecretReference {
    handle: Zeroizing<String>,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            handle: Zeroizing::new(self.handle.to_string()),
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

impl SecretReference {
    /// Construct an opaque SigV4 handle bound to one exact scope.
    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsNeptuneGraphScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, revision)
    }

    /// Construct an opaque handle without exposing its material in public
    /// state.  Native resolution is intentionally outside this crate.
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &AwsNeptuneGraphScope,
        revision: u64,
    ) -> Result<Self> {
        let handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            return Err(AwsNeptuneGraphResultError::InvalidIdentifier {
                field: "secret-reference",
            });
        }
        let reference_digest = Digest::from_parts(
            "aws-neptune-sigv4-secret-reference/v1",
            &[
                ("handle", handle.clone()),
                ("scope", scope.digest().as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            handle: Zeroizing::new(handle),
            reference_digest,
            scope_digest: scope.digest(),
            revision,
            revoked: false,
        })
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
        self.handle.zeroize();
    }

    pub(crate) fn validate_against(&self, scope: &AwsNeptuneGraphScope) -> Result<()> {
        if self.revoked || self.scope_digest != scope.digest() || self.revision == 0 {
            Err(AwsNeptuneGraphResultError::SecretScopeMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &"sigv4")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

/// Explicit transport provenance.  All variants are non-native in Layer 1.
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

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn provider_receipt(self) -> bool {
        false
    }
}

/// Bounded row/byte/time limits for one ExecuteOpenCypherQuery proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryLimits {
    pub max_rows: u32,
    pub max_bytes: u64,
    pub timeout_ms: u64,
    pub max_pages: u16,
}

impl QueryLimits {
    pub fn new(max_rows: u32, max_bytes: u64, timeout_ms: u64, max_pages: u16) -> Result<Self> {
        let limits = Self {
            max_rows,
            max_bytes,
            timeout_ms,
            max_pages,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn layer_one() -> Self {
        Self {
            max_rows: MAX_RESULT_ROWS,
            max_bytes: MAX_RESULT_BYTES,
            timeout_ms: MAX_RESULT_TIME_MS,
            max_pages: MAX_RESULT_PAGES,
        }
    }

    pub const fn max_rows(self) -> u32 {
        self.max_rows
    }

    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    pub const fn timeout_ms(self) -> u64 {
        self.timeout_ms
    }

    pub const fn max_pages(self) -> u16 {
        self.max_pages
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_rows == 0
            || self.max_rows > MAX_RESULT_ROWS
            || self.max_bytes == 0
            || self.max_bytes > MAX_RESULT_BYTES
            || self.timeout_ms == 0
            || self.timeout_ms > MAX_RESULT_TIME_MS
            || self.max_pages == 0
            || self.max_pages > MAX_RESULT_PAGES
        {
            Err(AwsNeptuneGraphResultError::InvalidBounds)
        } else {
            Ok(())
        }
    }
}

/// A graph node projection with identifiers, labels, and properties replaced
/// by stable digests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeProjection {
    pub node_digest: Digest,
    pub labels_digest: Digest,
    pub properties_digest: Digest,
    pub property_count: u16,
}

impl NodeProjection {
    /// Hash a provider node immediately; raw values are not retained.
    pub fn from_public<I, K, V>(
        identifier: impl AsRef<[u8]>,
        labels: I,
        properties: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        K: AsRef<str>,
        V: AsRef<[u8]>,
    {
        let labels = labels
            .into_iter()
            .map(|label| label.as_ref().to_owned())
            .collect::<Vec<_>>();
        if labels.is_empty() || labels.len() > MAX_PROJECTION_FIELDS {
            return Err(AwsNeptuneGraphResultError::InvalidProjection);
        }
        let mut labels = labels;
        labels.sort_unstable();
        let properties = properties
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), Digest::from_text(value)))
            .collect::<Vec<_>>();
        if properties.len() > MAX_PROJECTION_FIELDS {
            return Err(AwsNeptuneGraphResultError::InvalidProjection);
        }
        let mut properties = properties;
        properties.sort_unstable();
        let labels_digest =
            Digest::from_parts("aws-neptune-node-labels/v1", &[("l", labels.join("\n"))]);
        let properties_digest = Digest::from_parts(
            "aws-neptune-node-properties/v1",
            &[(
                "p",
                properties
                    .iter()
                    .map(|(key, value)| format!("{key}:{}", value.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        Ok(Self {
            node_digest: Digest::from_parts(
                "aws-neptune-node/v1",
                &[("identifier", hex::encode(identifier.as_ref()))],
            ),
            labels_digest,
            properties_digest,
            property_count: properties.len() as u16,
        })
    }

    pub(crate) fn fixture(seed: &Digest) -> Self {
        Self {
            node_digest: Digest::from_parts(
                "aws-neptune-fixture-node/v1",
                &[("seed", seed.as_str().to_owned())],
            ),
            labels_digest: Digest::from_text("fixture-label"),
            properties_digest: Digest::from_text("fixture-properties"),
            property_count: 0,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.node_digest.validate()?;
        self.labels_digest.validate()?;
        self.properties_digest.validate()?;
        Ok(())
    }
}

/// A graph relationship projection whose endpoint and property material is
/// digest-only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgeProjection {
    pub edge_digest: Digest,
    pub relationship_type_digest: Digest,
    pub from_node_digest: Digest,
    pub to_node_digest: Digest,
    pub properties_digest: Digest,
    pub property_count: u16,
}

impl EdgeProjection {
    /// Hash a provider edge immediately; raw values are not retained.
    pub fn from_public<I, K, V>(
        identifier: impl AsRef<[u8]>,
        relationship_type: impl AsRef<str>,
        from_node_identifier: impl AsRef<[u8]>,
        to_node_identifier: impl AsRef<[u8]>,
        properties: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<[u8]>,
    {
        let properties = properties
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), Digest::from_text(value)))
            .collect::<Vec<_>>();
        if properties.len() > MAX_PROJECTION_FIELDS {
            return Err(AwsNeptuneGraphResultError::InvalidProjection);
        }
        let mut properties = properties;
        properties.sort_unstable();
        Ok(Self {
            edge_digest: Digest::from_parts(
                "aws-neptune-edge/v1",
                &[("identifier", hex::encode(identifier.as_ref()))],
            ),
            relationship_type_digest: Digest::from_parts(
                "aws-neptune-relationship-type/v1",
                &[("type", relationship_type.as_ref().to_owned())],
            ),
            from_node_digest: Digest::from_parts(
                "aws-neptune-node/v1",
                &[("identifier", hex::encode(from_node_identifier.as_ref()))],
            ),
            to_node_digest: Digest::from_parts(
                "aws-neptune-node/v1",
                &[("identifier", hex::encode(to_node_identifier.as_ref()))],
            ),
            properties_digest: Digest::from_parts(
                "aws-neptune-edge-properties/v1",
                &[(
                    "p",
                    properties
                        .iter()
                        .map(|(key, value)| format!("{key}:{}", value.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )],
            ),
            property_count: properties.len() as u16,
        })
    }

    pub(crate) fn fixture(seed: &Digest, from: &NodeProjection, to: &NodeProjection) -> Self {
        Self {
            edge_digest: Digest::from_parts(
                "aws-neptune-fixture-edge/v1",
                &[("seed", seed.as_str().to_owned())],
            ),
            relationship_type_digest: Digest::from_text("fixture-relationship"),
            from_node_digest: from.node_digest.clone(),
            to_node_digest: to.node_digest.clone(),
            properties_digest: Digest::from_text("fixture-properties"),
            property_count: 0,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.edge_digest.validate()?;
        self.relationship_type_digest.validate()?;
        self.from_node_digest.validate()?;
        self.to_node_digest.validate()?;
        self.properties_digest.validate()?;
        Ok(())
    }
}

/// One bounded graph result row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphRowProjection {
    pub row_digest: Digest,
    pub nodes: Vec<NodeProjection>,
    pub edges: Vec<EdgeProjection>,
    pub byte_size: u64,
}

impl GraphRowProjection {
    pub fn new(
        nodes: Vec<NodeProjection>,
        edges: Vec<EdgeProjection>,
        byte_size: u64,
    ) -> Result<Self> {
        if nodes.len() + edges.len() > MAX_PROJECTION_FIELDS
            || byte_size == 0
            || byte_size > MAX_RESULT_BYTES
        {
            return Err(AwsNeptuneGraphResultError::InvalidProjection);
        }
        for node in &nodes {
            node.validate()?;
        }
        for edge in &edges {
            edge.validate()?;
        }
        let row_digest = Digest::from_parts(
            "aws-neptune-graph-row/v1",
            &[
                (
                    "nodes",
                    nodes
                        .iter()
                        .map(|node| node.node_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "edges",
                    edges
                        .iter()
                        .map(|edge| edge.edge_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("bytes", byte_size.to_string()),
            ],
        );
        Ok(Self {
            row_digest,
            nodes,
            edges,
            byte_size,
        })
    }

    pub fn fixture(seed: &Digest, relationship: bool) -> Result<Self> {
        let first = NodeProjection::fixture(seed);
        let second = NodeProjection::fixture(&Digest::from_parts(
            "aws-neptune-fixture-second-node/v1",
            &[("seed", seed.as_str().to_owned())],
        ));
        let edges = if relationship {
            vec![EdgeProjection::fixture(seed, &first, &second)]
        } else {
            Vec::new()
        };
        Self::new(vec![first, second], edges, 256)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.byte_size == 0
            || self.byte_size > MAX_RESULT_BYTES
            || self.nodes.len() + self.edges.len() > MAX_PROJECTION_FIELDS
        {
            return Err(AwsNeptuneGraphResultError::InvalidProjection);
        }
        for node in &self.nodes {
            node.validate()?;
        }
        for edge in &self.edges {
            edge.validate()?;
        }
        let recomputed = Self::new(self.nodes.clone(), self.edges.clone(), self.byte_size)?;
        if recomputed.row_digest != self.row_digest {
            return Err(AwsNeptuneGraphResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Evidence states exposed by the bounded provider seam.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NeptuneEvidenceState {
    Present,
    Empty,
    Partial,
    Timeout,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
}

impl NeptuneEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Present | Self::Empty)
    }

    pub const fn review_eligible(self) -> bool {
        matches!(self, Self::Present | Self::Empty)
    }
}

/// Why a proposal is partial.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    MorePages,
    RowLimit,
    ByteLimit,
    PageLimit,
    Timeout,
}

/// Query and result evidence digest fences.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub query_template_digest: Digest,
    pub parameter_digest: Digest,
    pub query_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
}

/// Digest-only bounded result evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NeptuneGraphEvidence {
    pub state: NeptuneEvidenceState,
    pub partial_reason: Option<PartialReason>,
    pub row_count: u32,
    pub node_count: u32,
    pub edge_count: u32,
    pub response_bytes: u64,
    pub elapsed_ms: u64,
    pub page_count: u16,
    pub result_digest: Digest,
    pub digests: EvidenceDigests,
    pub provenance: TransportProvenance,
}

impl NeptuneGraphEvidence {
    pub(crate) fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-neptune-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                (
                    "partial",
                    self.partial_reason
                        .map_or_else(|| "none".to_owned(), |reason| format!("{reason:?}")),
                ),
                ("rows", self.row_count.to_string()),
                ("nodes", self.node_count.to_string()),
                ("edges", self.edge_count.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("elapsed", self.elapsed_ms.to_string()),
                ("pages", self.page_count.to_string()),
                ("result", self.result_digest.as_str().to_owned()),
                ("scope", self.digests.scope_digest.as_str().to_owned()),
                ("query", self.digests.query_digest.as_str().to_owned()),
                (
                    "parameter",
                    self.digests.parameter_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}
