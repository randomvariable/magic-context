use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::db;

pub const CONFIG_CONTENT_MAX_BYTES: usize = 256 * 1024;
pub const PROJECT_PATH_MAX_BYTES: usize = 4096;
pub const PROJECT_CONFIGS_LIMIT_DEFAULT: usize = 100;
pub const PROJECT_CONFIGS_LIMIT_MAX: usize = 200;

/// Resolves paths to magic-context config files.
pub fn resolve_user_config_path() -> PathBuf {
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_default().join(".config"));
    config_dir.join("opencode").join("magic-context.jsonc")
}

fn resolve_home_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(home) = std::env::var_os("MAGIC_CONTEXT_DASHBOARD_TEST_HOME") {
        return PathBuf::from(home);
    }

    dirs::home_dir().unwrap_or_default()
}

/// Resolves the Pi user-level magic-context config path.
pub fn resolve_pi_config_path() -> PathBuf {
    resolve_home_dir()
        .join(".pi")
        .join("agent")
        .join("magic-context.jsonc")
}

/// Resolve the active magic-context config path for a project.
/// Checks root first, then `.opencode/` alt path. Returns the first that exists,
/// or root path as default for new config creation.
pub fn resolve_project_config_path(project_path: &str) -> PathBuf {
    let root_config = PathBuf::from(project_path).join("magic-context.jsonc");
    if root_config.exists() {
        return root_config;
    }
    let alt_config = PathBuf::from(project_path)
        .join(".opencode")
        .join("magic-context.jsonc");
    if alt_config.exists() {
        return alt_config;
    }
    // Default to root path for new configs
    root_config
}

fn resolve_xdg_data_home() -> PathBuf {
    std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_default()
                .join(".local")
                .join("share")
        })
}

fn canonicalize_existing_dir(path: &Path) -> Result<PathBuf, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("Invalid project path: {e}"))?;
    if !metadata.is_dir() {
        return Err("projectPath must point to an existing directory".to_string());
    }
    path.canonicalize()
        .map_err(|e| format!("Invalid project path: {e}"))
}

fn project_worktrees_from_opencode_db() -> Result<Vec<(String, PathBuf)>, String> {
    let opencode_db = db::resolve_opencode_db_path()
        .unwrap_or_else(|| resolve_xdg_data_home().join("opencode").join("opencode.db"));
    if !opencode_db.exists() {
        return Err("OpenCode project database not found".to_string());
    }

    let conn = rusqlite::Connection::open_with_flags(
        &opencode_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("Failed to open OpenCode project database: {e}"))?;

    let mut stmt = conn
        .prepare("SELECT name, worktree FROM project")
        .map_err(|e| format!("Failed to query OpenCode projects: {e}"))?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                row.get::<_, String>(1)?,
            ))
        })
        .map_err(|e| format!("Failed to query OpenCode projects: {e}"))?;

    let mut projects = Vec::new();
    for row in rows {
        let (name, worktree) =
            row.map_err(|e| format!("Failed to read OpenCode project row: {e}"))?;
        if let Ok(canonical_worktree) = canonicalize_existing_dir(Path::new(&worktree)) {
            projects.push((name, canonical_worktree));
        }
    }

    Ok(projects)
}

fn checked_read_existing_config(path: &Path) -> Result<String, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("Failed to stat config: {e}"))?;
    if metadata.len() > CONFIG_CONTENT_MAX_BYTES as u64 {
        return Err(format!(
            "config exceeds max size of {} bytes",
            CONFIG_CONTENT_MAX_BYTES
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {e}"))
}

fn canonicalize_existing_target(
    canonical_project_dir: &Path,
    candidate: &Path,
    reject_parent_symlink: bool,
) -> Result<Option<PathBuf>, String> {
    let metadata = match std::fs::symlink_metadata(candidate) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("Failed to stat config path: {err}")),
    };

    if metadata.file_type().is_symlink() {
        return Err(format!(
            "config path must not be a symlink: {}",
            candidate.display()
        ));
    }
    if !metadata.is_file() {
        return Ok(None);
    }

    if reject_parent_symlink {
        let parent = candidate
            .parent()
            .ok_or_else(|| "config path has no parent".to_string())?;
        let parent_meta = std::fs::symlink_metadata(parent)
            .map_err(|e| format!("Failed to stat config parent: {e}"))?;
        if parent_meta.file_type().is_symlink() {
            return Err(format!(
                "config parent must not be a symlink: {}",
                parent.display()
            ));
        }
    }

    let canonical_target = candidate
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize config path: {e}"))?;
    if !canonical_target.starts_with(canonical_project_dir) {
        return Err("config path escapes project directory".to_string());
    }

    Ok(Some(canonical_target))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigFile {
    pub path: String,
    pub exists: bool,
    pub content: String,
    pub source: String, // "user" or "project"
}

pub type ConfigFileResponse = ConfigFile;

pub fn read_config_checked(path: &Path, source: &str) -> Result<ConfigFile, String> {
    let exists = path.exists();
    let content = if exists {
        checked_read_existing_config(path)?
    } else {
        String::new()
    };

    Ok(ConfigFile {
        path: path.to_string_lossy().to_string(),
        exists,
        content,
        source: source.to_string(),
    })
}

pub fn canonicalize_known_project_dir(project_path: &str) -> Result<PathBuf, String> {
    let trimmed = project_path.trim();
    if trimmed.is_empty() {
        return Err("projectPath must be non-empty".to_string());
    }
    if trimmed.len() > PROJECT_PATH_MAX_BYTES {
        return Err(format!(
            "projectPath exceeds max size of {} bytes",
            PROJECT_PATH_MAX_BYTES
        ));
    }

    let path = Path::new(trimmed);
    if !path.is_absolute() {
        return Err("projectPath must be absolute".to_string());
    }

    let canonical_project_dir = canonicalize_existing_dir(path)?;
    let known_projects = project_worktrees_from_opencode_db()?;
    if known_projects
        .iter()
        .any(|(_, known_worktree)| known_worktree == &canonical_project_dir)
    {
        Ok(canonical_project_dir)
    } else {
        Err("projectPath is not a known OpenCode project worktree".to_string())
    }
}

pub fn resolve_existing_project_config_target(
    canonical_project_dir: &Path,
) -> Result<PathBuf, String> {
    let root_config = canonical_project_dir.join("magic-context.jsonc");
    if let Some(root) = canonicalize_existing_target(canonical_project_dir, &root_config, false)? {
        return Ok(root);
    }

    let alt_config = canonical_project_dir
        .join(".opencode")
        .join("magic-context.jsonc");
    if let Some(alt) = canonicalize_existing_target(canonical_project_dir, &alt_config, true)? {
        return Ok(alt);
    }

    Err("No existing project config found for browser Phase 3".to_string())
}

pub fn read_config(path: &PathBuf, source: &str) -> ConfigFile {
    let exists = path.exists();
    let content = if exists {
        std::fs::read_to_string(path).unwrap_or_default()
    } else {
        String::new()
    };

    ConfigFile {
        path: path.to_string_lossy().to_string(),
        exists,
        content,
        source: source.to_string(),
    }
}

pub fn write_config(path: &PathBuf, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    std::fs::write(path, content).map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

#[cfg_attr(feature = "desktop", tauri::command(async))]
pub fn read_pi_config() -> Result<ConfigFileResponse, String> {
    let path = resolve_pi_config_path();
    read_config_checked(&path, "pi")
}

#[cfg_attr(feature = "desktop", tauri::command(async))]
pub fn write_pi_config(content: String) -> Result<(), String> {
    let path = resolve_pi_config_path();
    write_config(&path, &content)
}

#[cfg_attr(feature = "desktop", tauri::command)]
pub fn pi_config_path() -> String {
    resolve_pi_config_path().to_string_lossy().to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProjectConfigEntry {
    pub project_name: String,
    pub worktree: String,
    pub config_path: String,
    pub exists: bool,
    pub alt_config_path: Option<String>,
    pub alt_exists: bool,
}

/// Discover projects with magic-context config files by scanning OpenCode project worktrees.
pub fn discover_project_configs() -> Vec<ProjectConfigEntry> {
    let rows = match project_worktrees_from_opencode_db() {
        Ok(rows) => rows,
        Err(_) => return vec![],
    };

    let mut entries = Vec::new();
    for (name, canonical_worktree) in rows {
        let worktree = canonical_worktree.to_string_lossy().to_string();
        let root_config = canonical_worktree.join("magic-context.jsonc");
        let alt_config = canonical_worktree
            .join(".opencode")
            .join("magic-context.jsonc");
        let root_exists = root_config.exists();
        let alt_exists = alt_config.exists();

        // Only include projects that have at least one config file
        if root_exists || alt_exists {
            let display_name = if name.is_empty() {
                std::path::Path::new(&worktree)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| worktree.clone())
            } else {
                name
            };

            entries.push(ProjectConfigEntry {
                project_name: display_name,
                worktree: worktree.clone(),
                config_path: root_config.to_string_lossy().to_string(),
                exists: root_exists,
                alt_config_path: Some(alt_config.to_string_lossy().to_string()),
                alt_exists,
            });
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi_config_path_and_read_cover_missing_and_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("MAGIC_CONTEXT_DASHBOARD_TEST_HOME", dir.path());

        let expected = dir.path().join(".pi/agent/magic-context.jsonc");
        assert_eq!(resolve_pi_config_path(), expected);
        assert_eq!(pi_config_path(), expected.to_string_lossy());

        let missing = read_pi_config().unwrap();
        assert_eq!(missing.path, expected.to_string_lossy());
        assert!(!missing.exists);
        assert_eq!(missing.content, "");
        assert_eq!(missing.source, "pi");

        let content = "{\n  \"enabled\": true\n}";
        write_pi_config(content.to_string()).unwrap();

        let existing = read_pi_config().unwrap();
        assert!(existing.exists);
        assert_eq!(existing.content, content);
        assert_eq!(existing.source, "pi");

        std::env::remove_var("MAGIC_CONTEXT_DASHBOARD_TEST_HOME");
    }
}
