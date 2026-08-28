use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    API_REVISION, CONTRACT_VERSION, MAX_DEFECT_BYTES, MAX_HOST_BYTES, MAX_IDENTIFIER_BYTES,
    MAX_ITEMS, MAX_VERSION_BYTES, PLUGIN_VERSION, PROVIDER_ID, TestRailError, Version,
    contract_digest,
};

/// Lower-case SHA-256 digest used for all binding, evidence, and replay fences.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    /// Hashes the deterministic serialized representation of a contract value.
    ///
    /// # Panics
    ///
    /// Panics only if `value` cannot be serialized. All values crossing this
    /// plugin boundary are required to implement infallible contract
    /// serialization.
    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("contract values must serialize");
        Self::from_bytes(&bytes)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn validate_text(value: &str, label: &'static str, max_bytes: usize) -> Result<(), TestRailError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(TestRailError::InvalidInput(label));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), TestRailError> {
    validate_text(value, label, MAX_IDENTIFIER_BYTES)
}

fn canonical_u64s<I>(values: I, label: &'static str) -> Result<Vec<u64>, TestRailError>
where
    I: IntoIterator<Item = u64>,
{
    let mut values: Vec<u64> = values.into_iter().collect();
    if values.contains(&0) {
        return Err(TestRailError::InvalidInput(label));
    }
    values.sort_unstable();
    values.dedup();
    if values.len() > crate::MAX_ITEMS {
        return Err(TestRailError::InvalidInput(label));
    }
    Ok(values)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentity {
    pub origin: String,
    pub revision: u64,
}

impl HostIdentity {
    pub fn new(origin: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let mut origin = origin.into().trim().to_owned();
        while origin.ends_with('/') {
            origin.pop();
        }
        if !origin.starts_with("https://")
            || origin.len() <= "https://".len()
            || origin.len() > MAX_HOST_BYTES
            || origin.contains('?')
            || origin.contains('#')
            || origin[8..].contains('/')
            || origin[8..].chars().any(char::is_whitespace)
            || revision == 0
        {
            return Err(TestRailError::InvalidInput("TestRail HTTPS host origin"));
        }
        Ok(Self { origin, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestRailProjectIdentity {
    pub id: u64,
    pub name: String,
    pub revision: u64,
}

impl TestRailProjectIdentity {
    pub fn new(id: u64, name: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            id,
            name: name.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), TestRailError> {
        if self.id == 0 || self.revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail project identity"));
        }
        validate_text(&self.name, "TestRail project name", MAX_IDENTIFIER_BYTES)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

pub type ProjectIdentity = TestRailProjectIdentity;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuiteIdentity {
    pub id: u64,
    pub name: String,
    pub revision: u64,
}

impl SuiteIdentity {
    pub fn new(id: u64, name: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            id,
            name: name.into(),
            revision,
        };
        if identity.id == 0 || identity.revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail suite identity"));
        }
        validate_text(&identity.name, "TestRail suite name", MAX_IDENTIFIER_BYTES)?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SectionIdentity {
    pub id: u64,
    pub name: String,
    pub revision: u64,
}

impl SectionIdentity {
    pub fn new(id: u64, name: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            id,
            name: name.into(),
            revision,
        };
        if identity.id == 0 || identity.revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail section identity"));
        }
        validate_text(
            &identity.name,
            "TestRail section name",
            MAX_IDENTIFIER_BYTES,
        )?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunIdentity {
    pub id: u64,
    pub name: String,
    /// Local registration revision for the exact run binding.
    pub revision: u64,
    /// TestRail `updated_on` timestamp captured by the binding.
    pub updated_on: u64,
    pub due_on: Option<u64>,
}

impl RunIdentity {
    pub fn new(
        id: u64,
        name: impl Into<String>,
        revision: u64,
        updated_on: u64,
    ) -> Result<Self, TestRailError> {
        Self::with_due_on(id, name, revision, updated_on, None)
    }

    pub fn with_due_on(
        id: u64,
        name: impl Into<String>,
        revision: u64,
        updated_on: u64,
        due_on: Option<u64>,
    ) -> Result<Self, TestRailError> {
        let identity = Self {
            id,
            name: name.into(),
            revision,
            updated_on,
            due_on,
        };
        if identity.id == 0 || identity.revision == 0 || identity.updated_on == 0 {
            return Err(TestRailError::InvalidInput("TestRail run identity"));
        }
        validate_text(&identity.name, "TestRail run name", MAX_IDENTIFIER_BYTES)?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestIdentity {
    pub id: u64,
    pub case_id: Option<u64>,
    pub title: String,
    pub revision: u64,
}

impl TestIdentity {
    pub fn new(
        id: u64,
        case_id: Option<u64>,
        title: impl Into<String>,
        revision: u64,
    ) -> Result<Self, TestRailError> {
        let identity = Self {
            id,
            case_id,
            title: title.into(),
            revision,
        };
        if identity.id == 0 || identity.case_id == Some(0) || identity.revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail test identity"));
        }
        validate_text(
            &identity.title,
            "TestRail test title",
            MAX_IDENTIFIER_BYTES * 4,
        )?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultScope {
    pub result_ids: Vec<u64>,
    pub revision: u64,
}

impl ResultScope {
    pub fn new(
        result_ids: impl IntoIterator<Item = u64>,
        revision: u64,
    ) -> Result<Self, TestRailError> {
        if revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail result revision"));
        }
        Ok(Self {
            result_ids: canonical_u64s(result_ids, "TestRail result IDs")?,
            revision,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusIdentity {
    pub id: u16,
    pub label: String,
    pub revision: u64,
}

impl StatusIdentity {
    pub fn new(id: u16, label: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            id,
            label: label.into(),
            revision,
        };
        if identity.id == 0 || identity.revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail status identity"));
        }
        validate_text(
            &identity.label,
            "TestRail status label",
            MAX_IDENTIFIER_BYTES,
        )?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefectIdentity {
    pub key: String,
    pub revision: u64,
}

impl DefectIdentity {
    pub fn new(key: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            key: key.into(),
            revision,
        };
        if identity.revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail defect revision"));
        }
        validate_text(&identity.key, "TestRail defect key", MAX_DEFECT_BYTES)?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum CommitOrRelease {
    Commit { sha: String, revision: u64 },
    Release { name: String, revision: u64 },
}

impl CommitOrRelease {
    pub fn commit(sha: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let sha = sha.into().to_ascii_lowercase();
        if revision == 0
            || !(7..=128).contains(&sha.len())
            || !sha.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(TestRailError::InvalidInput("source commit SHA"));
        }
        Ok(Self::Commit { sha, revision })
    }

    pub fn release(name: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let name = name.into();
        if revision == 0 {
            return Err(TestRailError::InvalidInput("source release"));
        }
        validate_text(&name, "source release", MAX_VERSION_BYTES)?;
        Ok(Self::Release { name, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn revision(&self) -> u64 {
        match self {
            Self::Commit { revision, .. } | Self::Release { revision, .. } => *revision,
        }
    }

    pub fn binding_value(&self) -> &str {
        match self {
            Self::Commit { sha, .. } => sha,
            Self::Release { name, .. } => name,
        }
    }
}

pub type SourceReference = CommitOrRelease;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionIdentity {
    pub id: String,
    pub revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            id: id.into(),
            revision,
        };
        if identity.revision == 0 {
            return Err(TestRailError::InvalidInput("Mission revision"));
        }
        validate_identifier(&identity.id, "Mission ID")?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HartevoProjectIdentity {
    pub id: String,
    pub revision: u64,
}

impl HartevoProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            id: id.into(),
            revision,
        };
        if identity.revision == 0 {
            return Err(TestRailError::InvalidInput("Hartevo Project revision"));
        }
        validate_identifier(&identity.id, "Hartevo Project ID")?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

pub type ProjectScopeIdentity = HartevoProjectIdentity;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductIdentity {
    pub id: String,
    pub revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, TestRailError> {
        let identity = Self {
            id: id.into(),
            revision,
        };
        if identity.revision == 0 {
            return Err(TestRailError::InvalidInput("Work Product revision"));
        }
        validate_identifier(&identity.id, "Work Product ID")?;
        Ok(identity)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRailPermission {
    HostRead,
    ProjectRead,
    SuiteRead,
    SectionRead,
    RunRead,
    TestRead,
    ResultRead,
    StatusRead,
    DefectMetadataRead,
    SourceRead,
    MissionScope,
}

impl TestRailPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostRead => "host.read",
            Self::ProjectRead => "project.read",
            Self::SuiteRead => "suite.read",
            Self::SectionRead => "section.read",
            Self::RunRead => "run.read",
            Self::TestRead => "test.read",
            Self::ResultRead => "result.read",
            Self::StatusRead => "status.read",
            Self::DefectMetadataRead => "defect.metadata.read",
            Self::SourceRead => "source.read",
            Self::MissionScope => "mission.scope",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<TestRailPermission>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    /// Returns the complete Layer-1 read-only permission set.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time permission list violates the
    /// invariants enforced by [`Self::new`].
    pub fn read_only() -> Self {
        let permissions: BTreeSet<_> = [
            TestRailPermission::HostRead,
            TestRailPermission::ProjectRead,
            TestRailPermission::SuiteRead,
            TestRailPermission::SectionRead,
            TestRailPermission::RunRead,
            TestRailPermission::TestRead,
            TestRailPermission::ResultRead,
            TestRailPermission::StatusRead,
            TestRailPermission::DefectMetadataRead,
            TestRailPermission::SourceRead,
            TestRailPermission::MissionScope,
        ]
        .into_iter()
        .collect();
        Self::new(permissions).expect("read-only permission snapshot is valid")
    }

    pub fn new(
        permissions: impl IntoIterator<Item = TestRailPermission>,
    ) -> Result<Self, TestRailError> {
        let permissions: BTreeSet<_> = permissions.into_iter().collect();
        let required = Self::read_only_permissions();
        if required
            .iter()
            .any(|permission| !permissions.contains(permission))
        {
            return Err(TestRailError::PermissionDrift);
        }
        let digest = Digest::from_serializable(&permissions);
        Ok(Self {
            permissions,
            digest,
        })
    }

    fn read_only_permissions() -> BTreeSet<TestRailPermission> {
        [
            TestRailPermission::HostRead,
            TestRailPermission::ProjectRead,
            TestRailPermission::SuiteRead,
            TestRailPermission::SectionRead,
            TestRailPermission::RunRead,
            TestRailPermission::TestRead,
            TestRailPermission::ResultRead,
            TestRailPermission::StatusRead,
            TestRailPermission::DefectMetadataRead,
            TestRailPermission::SourceRead,
            TestRailPermission::MissionScope,
        ]
        .into_iter()
        .collect()
    }

    pub fn validate(&self) -> Result<(), TestRailError> {
        let expected = Digest::from_serializable(&self.permissions);
        if expected != self.digest {
            return Err(TestRailError::TamperDetected);
        }
        let required = Self::read_only_permissions();
        if required
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(TestRailError::PermissionDrift);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn allows(&self, permission: TestRailPermission) -> bool {
        self.permissions.contains(&permission)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdentity {
    pub id: String,
    pub api_revision: String,
    pub provider_revision: u64,
}

impl ProviderIdentity {
    pub fn new(provider_revision: u64, id: impl Into<String>) -> Result<Self, TestRailError> {
        let identity = Self {
            id: id.into(),
            api_revision: API_REVISION.to_owned(),
            provider_revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn with_api_revision(
        provider_revision: u64,
        id: impl Into<String>,
        api_revision: impl Into<String>,
    ) -> Result<Self, TestRailError> {
        let identity = Self {
            id: id.into(),
            api_revision: api_revision.into(),
            provider_revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), TestRailError> {
        if self.provider_revision == 0 {
            return Err(TestRailError::InvalidInput("provider revision"));
        }
        validate_identifier(&self.id, "provider ID")?;
        validate_identifier(&self.api_revision, "provider API revision")
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestRailScope {
    pub api_revision: String,
    pub host: HostIdentity,
    pub project: TestRailProjectIdentity,
    pub suite: SuiteIdentity,
    pub section: SectionIdentity,
    pub run: RunIdentity,
    pub tests: Vec<TestIdentity>,
    pub result: ResultScope,
    pub statuses: Vec<StatusIdentity>,
    pub defects: Vec<DefectIdentity>,
    pub source: CommitOrRelease,
    pub mission: MissionIdentity,
    #[serde(rename = "hartevoProject")]
    pub hartevo_project: HartevoProjectIdentity,
    pub work_product: WorkProductIdentity,
    pub permissions: BTreeSet<TestRailPermission>,
    pub allowed_status_ids: BTreeSet<u16>,
}

impl TestRailScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: HostIdentity,
        project: TestRailProjectIdentity,
        suite: SuiteIdentity,
        section: SectionIdentity,
        run: RunIdentity,
        tests: impl IntoIterator<Item = TestIdentity>,
        result: ResultScope,
        statuses: impl IntoIterator<Item = StatusIdentity>,
        defects: impl IntoIterator<Item = DefectIdentity>,
        source: CommitOrRelease,
        mission: MissionIdentity,
        hartevo_project: HartevoProjectIdentity,
        work_product: WorkProductIdentity,
        permissions: impl IntoIterator<Item = TestRailPermission>,
    ) -> Result<Self, TestRailError> {
        let tests = canonical_tests(tests)?;
        let statuses = canonical_statuses(statuses)?;
        let defects = canonical_defects(defects)?;
        let permissions: BTreeSet<_> = permissions.into_iter().collect();
        let allowed_status_ids = if statuses.is_empty() {
            [1, 2, 3, 4, 5].into_iter().collect()
        } else {
            statuses.iter().map(|status| status.id).collect()
        };
        let scope = Self {
            api_revision: API_REVISION.to_owned(),
            host,
            project,
            suite,
            section,
            run,
            tests,
            result,
            statuses,
            defects,
            source,
            mission,
            hartevo_project,
            work_product,
            permissions,
            allowed_status_ids,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_api_revision(
        mut self,
        api_revision: impl Into<String>,
    ) -> Result<Self, TestRailError> {
        self.api_revision = api_revision.into();
        self.validate()?;
        Ok(self)
    }

    pub fn with_allowed_status_ids(
        mut self,
        allowed_status_ids: impl IntoIterator<Item = u16>,
    ) -> Result<Self, TestRailError> {
        self.allowed_status_ids = allowed_status_ids.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), TestRailError> {
        if self.api_revision != API_REVISION {
            return Err(TestRailError::UnsupportedApiVersion);
        }
        HostIdentity::new(self.host.origin.clone(), self.host.revision)?;
        self.project.validate()?;
        SuiteIdentity::new(self.suite.id, self.suite.name.clone(), self.suite.revision)?;
        SectionIdentity::new(
            self.section.id,
            self.section.name.clone(),
            self.section.revision,
        )?;
        RunIdentity::with_due_on(
            self.run.id,
            self.run.name.clone(),
            self.run.revision,
            self.run.updated_on,
            self.run.due_on,
        )?;
        if self.tests.len() > MAX_ITEMS {
            return Err(TestRailError::InvalidInput("TestRail tests"));
        }
        if self.tests.iter().any(|test| test.revision == 0) {
            return Err(TestRailError::InvalidInput("TestRail test revision"));
        }
        self.result.result_ids.iter().try_for_each(|id| {
            if *id == 0 {
                Err(TestRailError::InvalidInput("TestRail result ID"))
            } else {
                Ok(())
            }
        })?;
        if self.result.revision == 0 {
            return Err(TestRailError::InvalidInput("TestRail result revision"));
        }
        if self.statuses.iter().any(|status| status.revision == 0) {
            return Err(TestRailError::InvalidInput("TestRail status revision"));
        }
        if self.allowed_status_ids.is_empty() {
            return Err(TestRailError::InvalidInput("TestRail status allowlist"));
        }
        for status in &self.statuses {
            if !self.allowed_status_ids.contains(&status.id) {
                return Err(TestRailError::StatusDrift);
            }
        }
        for defect in &self.defects {
            defect.digest();
        }
        self.source.digest();
        self.mission.digest();
        self.hartevo_project.digest();
        self.work_product.digest();
        if self.permissions.is_empty() {
            return Err(TestRailError::PermissionDrift);
        }
        let required_permissions: BTreeSet<_> = [
            TestRailPermission::HostRead,
            TestRailPermission::ProjectRead,
            TestRailPermission::SuiteRead,
            TestRailPermission::SectionRead,
            TestRailPermission::RunRead,
            TestRailPermission::TestRead,
            TestRailPermission::ResultRead,
            TestRailPermission::StatusRead,
            TestRailPermission::DefectMetadataRead,
            TestRailPermission::SourceRead,
            TestRailPermission::MissionScope,
        ]
        .into_iter()
        .collect();
        if required_permissions
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(TestRailError::PermissionDrift);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn version_digest(&self) -> Digest {
        Digest::from_serializable(&(PLUGIN_VERSION, CONTRACT_VERSION))
    }

    pub fn contract_digest(&self) -> Digest {
        contract_digest()
    }

    pub fn host_digest(&self) -> Digest {
        self.host.digest()
    }
    pub fn project_digest(&self) -> Digest {
        self.project.digest()
    }
    pub fn suite_digest(&self) -> Digest {
        self.suite.digest()
    }
    pub fn section_digest(&self) -> Digest {
        self.section.digest()
    }
    pub fn run_digest(&self) -> Digest {
        self.run.digest()
    }
    pub fn test_digest(&self) -> Digest {
        Digest::from_serializable(&self.tests)
    }
    pub fn result_digest(&self) -> Digest {
        self.result.digest()
    }
    pub fn status_digest(&self) -> Digest {
        Digest::from_serializable(&self.statuses)
    }
    pub fn defect_digest(&self) -> Digest {
        Digest::from_serializable(&self.defects)
    }
    pub fn source_digest(&self) -> Digest {
        self.source.digest()
    }
    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }
    pub fn hartevo_project_digest(&self) -> Digest {
        self.hartevo_project.digest()
    }
    pub fn work_product_digest(&self) -> Digest {
        self.work_product.digest()
    }
    pub fn permission_digest(&self) -> Digest {
        Digest::from_serializable(&self.permissions)
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.host.revision,
            self.project.revision,
            self.suite.revision,
            self.section.revision,
            self.run.revision,
            self.result.revision,
            self.tests
                .iter()
                .map(|test| test.revision)
                .collect::<Vec<_>>(),
            self.statuses
                .iter()
                .map(|status| status.revision)
                .collect::<Vec<_>>(),
            self.defects
                .iter()
                .map(|defect| defect.revision)
                .collect::<Vec<_>>(),
            self.source.revision(),
            self.mission.revision,
            self.hartevo_project.revision,
            self.work_product.revision,
        ))
    }

    pub fn expected_test_ids(&self) -> BTreeSet<u64> {
        self.tests.iter().map(|test| test.id).collect()
    }

    pub fn expected_result_ids(&self) -> BTreeSet<u64> {
        self.result.result_ids.iter().copied().collect()
    }
}

fn canonical_tests(
    values: impl IntoIterator<Item = TestIdentity>,
) -> Result<Vec<TestIdentity>, TestRailError> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_by_key(|value| value.id);
    if values.windows(2).any(|window| window[0].id == window[1].id) {
        return Err(TestRailError::InvalidInput("duplicate TestRail test"));
    }
    if values.len() > crate::MAX_ITEMS {
        return Err(TestRailError::InvalidInput("TestRail tests"));
    }
    Ok(values)
}

fn canonical_statuses(
    values: impl IntoIterator<Item = StatusIdentity>,
) -> Result<Vec<StatusIdentity>, TestRailError> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_by_key(|value| value.id);
    if values.windows(2).any(|window| window[0].id == window[1].id) {
        return Err(TestRailError::InvalidInput("duplicate TestRail status"));
    }
    Ok(values)
}

fn canonical_defects(
    values: impl IntoIterator<Item = DefectIdentity>,
) -> Result<Vec<DefectIdentity>, TestRailError> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_by(|left, right| left.key.cmp(&right.key));
    if values
        .windows(2)
        .any(|window| window[0].key == window[1].key)
    {
        return Err(TestRailError::InvalidInput("duplicate TestRail defect"));
    }
    if values.len() > crate::MAX_DEFECTS {
        return Err(TestRailError::InvalidInput("TestRail defects"));
    }
    Ok(values)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    ApiKey,
}

/// Opaque reference to API-key material held outside Layer 1.
///
/// The raw reference ID is hashed at construction and is never stored,
/// serialized, displayed, or exposed through an accessor.  This type
/// deliberately implements no `Serialize` or `Deserialize`.
pub struct SecretReference {
    kind: SecretReferenceKind,
    scope_digest: Digest,
    generation: u64,
    reference_digest: Digest,
    revoked: Arc<AtomicU8>,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            scope_digest: self.scope_digest.clone(),
            generation: self.generation,
            reference_digest: self.reference_digest.clone(),
            revoked: Arc::clone(&self.revoked),
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.scope_digest == other.scope_digest
            && self.generation == other.generation
            && self.reference_digest == other.reference_digest
            && self.is_revoked() == other.is_revoked()
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("reference_digest", &self.reference_digest)
            .field("revoked", &self.is_revoked())
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &TestRailScope,
        generation: u64,
    ) -> Result<Self, TestRailError> {
        Self::api_key(reference_id, scope, generation)
    }

    pub fn api_key(
        reference_id: impl AsRef<str>,
        scope: &TestRailScope,
        generation: u64,
    ) -> Result<Self, TestRailError> {
        let reference_id = reference_id.as_ref();
        validate_identifier(reference_id, "opaque API-key reference")?;
        if generation == 0 {
            return Err(TestRailError::InvalidSecretReference);
        }
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_serializable(&(
            reference_id,
            SecretReferenceKind::ApiKey,
            &scope_digest,
            generation,
        ));
        Ok(Self {
            kind: SecretReferenceKind::ApiKey,
            scope_digest,
            generation,
            reference_digest,
            revoked: Arc::new(AtomicU8::new(0)),
        })
    }

    pub fn kind(&self) -> SecretReferenceKind {
        self.kind
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire) != 0
    }

    pub fn revoke(&self) {
        self.revoked.store(1, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    fn as_u8(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Revoked => 1,
            Self::Reversed => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Revoked,
            2 => Self::Reversed,
            _ => Self::Active,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone)]
pub struct TestRailRegistration {
    pub scope: TestRailScope,
    pub provider: ProviderIdentity,
    pub permission_snapshot: PermissionSnapshot,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    secret: SecretReference,
    status: Arc<AtomicU8>,
}

impl PartialEq for TestRailRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope
            && self.provider == other.provider
            && self.permission_snapshot == other.permission_snapshot
            && self.registration_revision == other.registration_revision
            && self.registration_digest == other.registration_digest
            && self.secret == other.secret
            && self.state() == other.state()
    }
}

impl Eq for TestRailRegistration {}

impl TestRailRegistration {
    pub fn new(
        scope: TestRailScope,
        secret: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: ProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self, TestRailError> {
        scope.validate()?;
        permission_snapshot.validate()?;
        if registration_revision == 0 {
            return Err(TestRailError::InvalidInput("registration revision"));
        }
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(TestRailError::RegistrationMismatch);
        }
        if provider.id != PROVIDER_ID || provider.api_revision != API_REVISION {
            return Err(TestRailError::ProviderDrift);
        }
        let registration_digest = Digest::from_serializable(&RegistrationBindingMaterial {
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider: provider.clone(),
            permission_digest: permission_snapshot.digest.clone(),
            scope_digest: scope.scope_digest(),
            revision_digest: scope.revision_digest(),
            secret_reference_digest: secret.reference_digest.clone(),
            registration_revision,
        });
        Ok(Self {
            scope,
            provider,
            permission_snapshot,
            registration_revision,
            registration_digest,
            secret,
            status: Arc::new(AtomicU8::new(RegistrationStatus::Active.as_u8())),
        })
    }

    pub fn register(scope: TestRailScope, secret: SecretReference) -> Result<Self, TestRailError> {
        Self::new(
            scope,
            secret,
            PermissionSnapshot::read_only(),
            ProviderIdentity::new(1, PROVIDER_ID)?,
            1,
        )
    }

    pub fn scope(&self) -> &TestRailScope {
        &self.scope
    }
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }
    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }
    pub fn permissions(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
    pub fn state(&self) -> RegistrationStatus {
        RegistrationStatus::from_u8(self.status.load(Ordering::Acquire))
    }
    pub fn is_active(&self) -> bool {
        self.state() == RegistrationStatus::Active && !self.secret.is_revoked()
    }

    pub fn validate_integrity(&self) -> Result<(), TestRailError> {
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        if self.secret.scope_digest() != &self.scope.scope_digest() {
            return Err(TestRailError::RegistrationMismatch);
        }
        let expected = Digest::from_serializable(&RegistrationBindingMaterial {
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider: self.provider.clone(),
            permission_digest: self.permission_snapshot.digest.clone(),
            scope_digest: self.scope.scope_digest(),
            revision_digest: self.scope.revision_digest(),
            secret_reference_digest: self.secret.reference_digest.clone(),
            registration_revision: self.registration_revision,
        });
        if expected != self.registration_digest {
            return Err(TestRailError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), TestRailError> {
        self.validate_integrity()?;
        match self.state() {
            RegistrationStatus::Active if !self.secret.is_revoked() => Ok(()),
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                Err(TestRailError::RegistrationRevoked)
            }
            RegistrationStatus::Reversed => Err(TestRailError::RegistrationReversed),
        }
    }

    pub fn revoke(&self) -> Result<RevocationReceipt, TestRailError> {
        self.set_terminal(RegistrationStatus::Revoked)
    }

    pub fn reverse(&self) -> Result<RevocationReceipt, TestRailError> {
        self.set_terminal(RegistrationStatus::Reversed)
    }

    fn set_terminal(&self, status: RegistrationStatus) -> Result<RevocationReceipt, TestRailError> {
        if self
            .status
            .compare_exchange(
                RegistrationStatus::Active.as_u8(),
                status.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(TestRailError::RegistrationAlreadyTerminal);
        }
        self.secret.revoke();
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            state: status,
            revocation_digest: Digest::from_serializable(&(
                self.registration_digest.clone(),
                status,
            )),
        })
    }
}

impl Serialize for TestRailRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TestRailRegistration", 7)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("provider", &self.provider)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret.reference_digest)?;
        state.serialize_field("status", &self.state())?;
        state.end()
    }
}

impl fmt::Debug for TestRailRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestRailRegistration")
            .field("scope", &self.scope)
            .field("provider", &self.provider)
            .field("permission_snapshot", &self.permission_snapshot)
            .field("registration_revision", &self.registration_revision)
            .field("registration_digest", &self.registration_digest)
            .field("secret_reference", &self.secret)
            .field("status", &self.state())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub state: RegistrationStatus,
    pub revocation_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RegistrationBindingMaterial {
    plugin_version: Version,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TestRailRegistrationRegistry {
    registrations: VecDeque<TestRailRegistration>,
}

impl TestRailRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: TestRailRegistration,
    ) -> Result<Digest, TestRailError> {
        registration.validate_integrity()?;
        if self
            .registrations
            .iter()
            .any(|existing| existing.registration_digest == registration.registration_digest)
        {
            return Err(TestRailError::DuplicateRecording);
        }
        let digest = registration.registration_digest.clone();
        self.registrations.push_back(registration);
        Ok(digest)
    }

    pub fn revoke(&self, digest: &Digest) -> Result<RevocationReceipt, TestRailError> {
        let registration = self
            .registrations
            .iter()
            .find(|registration| &registration.registration_digest == digest)
            .ok_or(TestRailError::RegistrationMismatch)?;
        registration.revoke()
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}
