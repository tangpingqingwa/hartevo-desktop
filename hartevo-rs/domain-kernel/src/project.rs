use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ProjectId, TenantId};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    LocalExisting,
    LocalNew,
    LocalEncryptedSync,
    Cloud,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectDataCell {
    Us,
    Eu,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    #[serde(default = "legacy_tenant_id")]
    pub tenant_id: TenantId,
    pub id: ProjectId,
    pub name: String,
    pub description: String,
    pub storage_mode: StorageMode,
    #[serde(default)]
    pub data_cell: Option<ProjectDataCell>,
    pub workspace_roots: Vec<PathBuf>,
    pub revision: u64,
}

impl Project {
    pub fn create_local(
        tenant_id: TenantId,
        id: ProjectId,
        name: impl Into<String>,
        description: impl Into<String>,
        root: impl Into<PathBuf>,
        storage_mode: StorageMode,
    ) -> Result<Self, ProjectError> {
        if matches!(storage_mode, StorageMode::Cloud) {
            return Err(ProjectError::CloudModeForLocalProject);
        }

        let name = name.into().trim().to_owned();
        if name.is_empty() {
            return Err(ProjectError::EmptyName);
        }

        let root = root.into();
        if !root.is_absolute() {
            return Err(ProjectError::WorkspaceRootNotAbsolute(root));
        }

        Ok(Self {
            tenant_id,
            id,
            name,
            description: description.into(),
            storage_mode,
            data_cell: None,
            workspace_roots: vec![root],
            revision: 1,
        })
    }

    pub fn contains_path(&self, path: &Path) -> bool {
        self.workspace_roots
            .iter()
            .any(|root| path.starts_with(root))
    }

    pub fn select_data_cell(&mut self, cell: ProjectDataCell) -> Result<(), ProjectError> {
        if self.storage_mode != StorageMode::LocalEncryptedSync {
            return Err(ProjectError::DataCellRequiresEncryptedSync);
        }
        match self.data_cell {
            Some(current) if current == cell => Ok(()),
            Some(_) => Err(ProjectError::DataCellIsImmutable),
            None => {
                self.data_cell = Some(cell);
                self.revision = self
                    .revision
                    .checked_add(1)
                    .ok_or(ProjectError::RevisionOverflow)?;
                Ok(())
            }
        }
    }

    pub fn update_metadata(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<bool, ProjectError> {
        let name = name.into().trim().to_owned();
        if name.is_empty() {
            return Err(ProjectError::EmptyName);
        }
        let description = description.into();
        if self.name == name && self.description == description {
            return Ok(false);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(ProjectError::RevisionOverflow)?;
        self.name = name;
        self.description = description;
        self.revision = next_revision;
        Ok(true)
    }
}

fn legacy_tenant_id() -> TenantId {
    TenantId::from("legacy-local")
}

#[derive(Debug, Error, PartialEq)]
pub enum ProjectError {
    #[error("project name cannot be empty")]
    EmptyName,
    #[error("workspace root must be absolute: {0}")]
    WorkspaceRootNotAbsolute(PathBuf),
    #[error("a local project cannot use cloud-only storage mode")]
    CloudModeForLocalProject,
    #[error("a data Cell can only be selected for a local encrypted-sync project")]
    DataCellRequiresEncryptedSync,
    #[error("a project's US/EU data Cell cannot be changed in place")]
    DataCellIsImmutable,
    #[error("project revision overflow")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_project_rejects_relative_roots() {
        let result = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Launch",
            "",
            "relative/path",
            StorageMode::LocalExisting,
        );

        assert!(matches!(
            result,
            Err(ProjectError::WorkspaceRootNotAbsolute(_))
        ));
    }

    #[test]
    fn project_scope_is_path_bounded() {
        let project = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Launch",
            "",
            "/workspace/launch",
            StorageMode::LocalExisting,
        )
        .expect("valid project");

        assert!(project.contains_path(Path::new("/workspace/launch/brief.md")));
        assert!(!project.contains_path(Path::new("/workspace/other/brief.md")));
    }

    #[test]
    fn encrypted_sync_cell_is_explicit_and_immutable() {
        let mut project = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Launch",
            "",
            "/workspace/launch",
            StorageMode::LocalEncryptedSync,
        )
        .expect("encrypted project");
        project
            .select_data_cell(ProjectDataCell::Eu)
            .expect("select EU");
        assert_eq!(
            (project.data_cell, project.revision),
            (Some(ProjectDataCell::Eu), 2)
        );
        project
            .select_data_cell(ProjectDataCell::Eu)
            .expect("idempotent selection");
        assert_eq!(project.revision, 2);
        assert_eq!(
            project.select_data_cell(ProjectDataCell::Us),
            Err(ProjectError::DataCellIsImmutable)
        );
    }

    #[test]
    fn metadata_update_is_idempotent_and_advances_exactly_one_revision() {
        let mut project = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Launch",
            "Draft",
            "/workspace/launch",
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        assert!(
            project
                .update_metadata("Launch plan", "Reviewed")
                .expect("update")
        );
        assert_eq!(
            (project.name.as_str(), project.revision),
            ("Launch plan", 2)
        );
        assert!(
            !project
                .update_metadata("Launch plan", "Reviewed")
                .expect("idempotent update")
        );
        assert_eq!(project.revision, 2);
    }
}
