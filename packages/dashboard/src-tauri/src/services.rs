use crate::{config, db, embedding_probe, AppState};

pub const SMART_NOTES_LIMIT_MAX: usize = 200;
pub const SESSION_VIEWER_CONTENT_MAX_BYTES: usize = 64 * 1024;
pub const USER_MEMORIES_LIMIT_DEFAULT: usize = 200;
pub const USER_MEMORIES_LIMIT_MAX: usize = 500;
pub const USER_MEMORY_CANDIDATES_LIMIT_DEFAULT: usize = 100;
pub const USER_MEMORY_CANDIDATES_LIMIT_MAX: usize = 200;
pub const USER_MEMORY_CONTENT_MAX_BYTES: usize = 64 * 1024;
pub const LOG_ENTRIES_LIMIT_DEFAULT: usize = 500;

pub fn get_dashboard_schema_warning(state: &AppState) -> Option<i64> {
    state.dashboard_schema_warning_version()
}

pub fn get_db_health(state: &AppState) -> db::DbHealth {
    match state.get_db_path() {
        Ok(path) => db::get_db_health(&path),
        Err(_) => missing_db_health(),
    }
}

pub fn get_projects(state: &AppState) -> Result<Vec<db::ProjectInfo>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_projects(&conn).map_err(|e| e.to_string())
}

pub fn get_memories(
    state: &AppState,
    project: Option<String>,
    workspace_id: Option<i64>,
    status: Option<String>,
    category: Option<String>,
    search: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<db::Memory>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_memories(
        &conn,
        project.as_deref(),
        workspace_id,
        status.as_deref(),
        category.as_deref(),
        search.as_deref(),
        limit.unwrap_or(100),
        offset.unwrap_or(0),
    )
    .map_err(|e| e.to_string())
}

pub fn get_memory_stats(
    state: &AppState,
    project: Option<String>,
    workspace_id: Option<i64>,
) -> Result<db::MemoryStats, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_memory_stats(&conn, project.as_deref(), workspace_id).map_err(|e| e.to_string())
}

pub fn update_memory_status(
    state: &AppState,
    memory_id: i64,
    status: String,
) -> Result<(), String> {
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::update_memory_status(&mut conn, memory_id, &status).map_err(|e| e.to_string())
}

pub fn update_memory_content(
    state: &AppState,
    memory_id: i64,
    content: String,
) -> Result<(), String> {
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::update_memory_content(&mut conn, memory_id, &content).map_err(|e| e.to_string())
}

pub fn delete_memory(state: &AppState, memory_id: i64) -> Result<(), String> {
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::delete_memory(&mut conn, memory_id).map_err(|e| e.to_string())
}

pub fn bulk_update_memory_status(
    state: &AppState,
    memory_ids: Vec<i64>,
    status: String,
) -> Result<usize, String> {
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::bulk_update_memory_status(&mut conn, &memory_ids, &status).map_err(|e| e.to_string())
}

pub fn bulk_delete_memory(state: &AppState, memory_ids: Vec<i64>) -> Result<usize, String> {
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::bulk_delete_memory(&mut conn, &memory_ids).map_err(|e| e.to_string())
}

pub fn get_sessions(state: &AppState) -> Result<Vec<db::SessionSummary>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_sessions(&conn).map_err(|e| e.to_string())
}

pub fn list_sessions(filter: Option<db::SessionFilter>) -> Vec<db::SessionRow> {
    db::list_all_sessions(filter.unwrap_or_default())
}

pub fn list_sessions_paged(filter: Option<db::SessionFilter>) -> db::PagedSessions {
    db::list_sessions_paged(filter.unwrap_or_default())
}

pub fn get_session_detail(
    state: &AppState,
    harness: db::Harness,
    session_id: String,
) -> Result<db::SessionDetail, String> {
    let conn = state
        .get_db_path()
        .ok()
        .and_then(|path| db::open_readonly(&path).ok());
    db::get_session_detail(conn.as_ref(), harness, &session_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("session not found: {session_id}"))
}

pub fn get_session_messages(
    harness: db::Harness,
    session_id: String,
    limit: usize,
) -> Result<Vec<db::SessionMessageRow>, String> {
    let mut rows =
        db::get_session_messages_limited(harness, &session_id, limit).map_err(|e| e.to_string())?;
    for row in &mut rows {
        row.raw_json = serde_json::Value::Null;
    }
    Ok(rows)
}

pub fn get_session_cache_events(
    harness: db::Harness,
    session_id: String,
    limit: usize,
) -> Result<Vec<db::DbCacheEvent>, String> {
    Ok(db::get_session_cache_events(
        harness,
        &session_id,
        Some(limit),
        None,
    ))
}

pub fn get_session_cache_events_by_turns(
    harness: db::Harness,
    session_id: String,
    target_turns: usize,
) -> Result<Vec<db::DbCacheEvent>, String> {
    Ok(db::get_session_cache_events_by_turn_count(
        harness,
        &session_id,
        target_turns,
    ))
}

pub fn get_cache_events_from_db(
    limit: usize,
    since_timestamp: Option<i64>,
) -> Result<Vec<db::DbCacheEvent>, String> {
    Ok(db::get_cache_events_from_db(limit, since_timestamp))
}

pub fn get_log_entries(max_lines: usize) -> Result<Vec<crate::log_parser::LogEntry>, String> {
    let log_path = crate::log_parser::resolve_log_path();
    Ok(get_log_entries_from_path(&log_path, max_lines))
}

pub async fn get_available_models() -> Vec<String> {
    crate::model_discovery::discover_opencode_models().await
}

pub async fn get_available_pi_models() -> Vec<String> {
    crate::model_discovery::discover_pi_models().await
}

pub async fn test_embedding_endpoint_browser(
    endpoint: String,
    model: String,
    api_key: Option<String>,
    input_type: Option<String>,
    truncate: Option<String>,
) -> embedding_probe::EmbeddingProbeOutcome {
    embedding_probe::probe_embedding_endpoint_browser(embedding_probe::EmbeddingProbeOptions {
        endpoint,
        model,
        api_key,
        input_type,
        truncate,
        timeout_ms: 10_000,
    })
    .await
}

pub fn get_log_entries_from_path(
    log_path: &std::path::PathBuf,
    max_lines: usize,
) -> Vec<crate::log_parser::LogEntry> {
    crate::log_parser::read_log_tail_capped(
        log_path,
        max_lines,
        crate::log_parser::LOG_TAIL_READ_CAP_BYTES,
    )
    .into_iter()
    .map(crate::log_parser::redact_and_truncate_browser_entry)
    .map(|mut entry| {
        entry.raw = None;
        entry
    })
    .collect()
}

pub fn get_subagent_invocations(
    state: &AppState,
    session_id: String,
    limit: usize,
) -> Result<Vec<db::SubagentInvocation>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_subagent_invocations(&conn, &session_id, limit).map_err(|e| e.to_string())
}

pub fn get_subagent_totals_by_subagent(
    state: &AppState,
    session_id: String,
    limit: usize,
) -> Result<Vec<db::SubagentTotals>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_subagent_totals_by_subagent(&conn, &session_id, limit).map_err(|e| e.to_string())
}

pub fn get_project_key_files(
    state: &AppState,
    project_path: String,
    limit: usize,
) -> Result<Vec<db::KeyFileRow>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_project_key_files(&conn, &project_path, limit).map_err(|e| e.to_string())
}

pub fn get_compartments(
    state: &AppState,
    session_id: String,
    limit: usize,
) -> Result<Vec<db::Compartment>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_compartments(&conn, &session_id, limit).map_err(|e| e.to_string())
}

pub fn get_smart_notes(
    state: &AppState,
    project_path: String,
    limit: usize,
) -> Result<Vec<db::Note>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_smart_notes(&conn, &project_path, limit).map_err(|e| e.to_string())
}

pub fn update_session_fact(state: &AppState, fact_id: i64, content: String) -> Result<(), String> {
    validate_positive_id(fact_id, "factId")?;
    validate_content_size(&content)?;
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::update_session_fact(&mut conn, fact_id, &content).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn delete_session_fact(state: &AppState, fact_id: i64) -> Result<(), String> {
    validate_positive_id(fact_id, "factId")?;
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::delete_session_fact(&mut conn, fact_id).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn update_note(state: &AppState, note_id: i64, content: String) -> Result<(), String> {
    validate_positive_id(note_id, "noteId")?;
    validate_content_size(&content)?;
    let path = state.get_db_path()?;
    let conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::update_note(&conn, note_id, &content).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn delete_note(state: &AppState, note_id: i64) -> Result<(), String> {
    validate_positive_id(note_id, "noteId")?;
    let path = state.get_db_path()?;
    let conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::delete_note(&conn, note_id).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn dismiss_note(state: &AppState, note_id: i64) -> Result<(), String> {
    validate_positive_id(note_id, "noteId")?;
    let path = state.get_db_path()?;
    let conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::dismiss_note(&conn, note_id).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn get_user_memories(
    state: &AppState,
    status: Option<String>,
    limit: usize,
) -> Result<Vec<db::UserMemory>, String> {
    validate_user_memory_limit(limit)?;
    validate_user_memory_status(status.as_deref())?;
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_user_memories(&conn, status.as_deref(), limit).map_err(|e| e.to_string())
}

pub fn get_user_memory_candidates(
    state: &AppState,
    limit: usize,
) -> Result<Vec<db::UserMemoryCandidate>, String> {
    validate_user_memory_candidates_limit(limit)?;
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_user_memory_candidates(&conn, limit).map_err(|e| e.to_string())
}

pub fn dismiss_user_memory(state: &AppState, id: i64) -> Result<(), String> {
    validate_positive_id(id, "id")?;
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    let affected = db::dismiss_user_memory(&mut conn, id).map_err(|e| e.to_string())?;
    if affected {
        Ok(())
    } else {
        Err(format!("user memory not found: {id}"))
    }
}

pub fn delete_user_memory(state: &AppState, id: i64) -> Result<(), String> {
    validate_positive_id(id, "id")?;
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    let affected = db::delete_user_memory(&mut conn, id).map_err(|e| e.to_string())?;
    if affected {
        Ok(())
    } else {
        Err(format!("user memory not found: {id}"))
    }
}

pub fn update_user_memory_content(
    state: &AppState,
    id: i64,
    content: String,
) -> Result<(), String> {
    validate_positive_id(id, "id")?;
    validate_user_memory_update_content(&content)?;
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    let affected =
        db::update_user_memory_content(&mut conn, id, &content).map_err(|e| e.to_string())?;
    if affected {
        Ok(())
    } else {
        Err(format!("user memory not found: {id}"))
    }
}

pub fn delete_user_memory_candidate(state: &AppState, id: i64) -> Result<(), String> {
    validate_positive_id(id, "id")?;
    let path = state.get_db_path()?;
    let conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::delete_user_memory_candidate(&conn, id).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => format!("user memory candidate not found: {id}"),
        _ => e.to_string(),
    })
}

pub fn promote_user_memory_candidate(state: &AppState, id: i64) -> Result<(), String> {
    validate_positive_id(id, "id")?;
    let path = state.get_db_path()?;
    let mut conn = db::open_readwrite(&path).map_err(|e| e.to_string())?;
    db::promote_user_memory_candidate(&mut conn, id, USER_MEMORY_CONTENT_MAX_BYTES).map_err(|e| {
        match e {
            rusqlite::Error::QueryReturnedNoRows => {
                format!("user memory candidate not found: {id}")
            }
            rusqlite::Error::InvalidQuery => format!(
                "content exceeds max size of {} bytes",
                USER_MEMORY_CONTENT_MAX_BYTES
            ),
            _ => e.to_string(),
        }
    })
}

pub fn get_config(
    source: String,
    project_path: Option<String>,
) -> Result<config::ConfigFile, String> {
    match source.as_str() {
        "user" => {
            let path = config::resolve_user_config_path();
            config::read_config_checked(&path, "user")
        }
        "project" => {
            let project_path = project_path
                .ok_or_else(|| "projectPath is required for project source".to_string())?;
            let canonical_project_dir = config::canonicalize_known_project_dir(&project_path)?;
            let path = config::resolve_existing_project_config_target(&canonical_project_dir)?;
            config::read_config_checked(&path, "project")
        }
        other => Err(format!(
            "source must be one of: user, project (got {other})"
        )),
    }
}

pub fn save_config(source: String, content: String) -> Result<(), String> {
    validate_config_content_size(&content)?;
    match source.as_str() {
        "user" => {
            let path = config::resolve_user_config_path();
            config::write_config(&path, &content)
        }
        other => Err(format!(
            "Only user config editing is supported in V1 (got {other})"
        )),
    }
}

pub fn read_pi_config() -> Result<config::ConfigFileResponse, String> {
    let path = config::resolve_pi_config_path();
    config::read_config_checked(&path, "pi")
}

pub fn write_pi_config(content: String) -> Result<(), String> {
    validate_config_content_size(&content)?;
    let path = config::resolve_pi_config_path();
    config::write_config(&path, &content)
}

pub fn get_project_configs(limit: usize) -> Result<Vec<config::ProjectConfigEntry>, String> {
    validate_project_configs_limit(limit)?;
    let mut entries = config::discover_project_configs();
    entries.retain(|entry| {
        config::canonicalize_known_project_dir(&entry.worktree)
            .and_then(|canonical_project_dir| {
                config::resolve_existing_project_config_target(&canonical_project_dir)
            })
            .is_ok()
    });
    entries.sort_by(|a, b| {
        let a_name = a.project_name.to_ascii_lowercase();
        let b_name = b.project_name.to_ascii_lowercase();
        a_name.cmp(&b_name).then_with(|| {
            a.worktree
                .to_ascii_lowercase()
                .cmp(&b.worktree.to_ascii_lowercase())
        })
    });
    entries.truncate(limit);
    Ok(entries)
}

pub fn save_project_config(project_path: String, content: String) -> Result<(), String> {
    validate_config_content_size(&content)?;
    let canonical_project_dir = config::canonicalize_known_project_dir(&project_path)?;
    let path = config::resolve_existing_project_config_target(&canonical_project_dir)?;
    config::write_config(&path, &content)
}

fn validate_user_memory_status(status: Option<&str>) -> Result<(), String> {
    match status {
        None | Some("active") | Some("dismissed") => Ok(()),
        Some(other) => Err(format!(
            "status must be one of: active, dismissed (got {other})"
        )),
    }
}

fn validate_user_memory_limit(limit: usize) -> Result<(), String> {
    if limit == 0 {
        return Err("limit must be positive".to_string());
    }
    if limit > USER_MEMORIES_LIMIT_MAX {
        return Err(format!(
            "limit exceeds max value of {USER_MEMORIES_LIMIT_MAX}"
        ));
    }
    Ok(())
}

fn validate_user_memory_candidates_limit(limit: usize) -> Result<(), String> {
    if limit == 0 {
        return Err("limit must be positive".to_string());
    }
    if limit > USER_MEMORY_CANDIDATES_LIMIT_MAX {
        return Err(format!(
            "limit exceeds max value of {USER_MEMORY_CANDIDATES_LIMIT_MAX}"
        ));
    }
    Ok(())
}

fn validate_user_memory_update_content(content: &str) -> Result<(), String> {
    if content.trim().is_empty() {
        return Err("content must be non-empty".to_string());
    }
    if content.len() > USER_MEMORY_CONTENT_MAX_BYTES {
        return Err(format!(
            "content exceeds max size of {} bytes",
            USER_MEMORY_CONTENT_MAX_BYTES
        ));
    }
    Ok(())
}

fn validate_config_content_size(content: &str) -> Result<(), String> {
    let byte_len = content.len();
    if byte_len > config::CONFIG_CONTENT_MAX_BYTES {
        Err(format!(
            "content exceeds max size of {} bytes",
            config::CONFIG_CONTENT_MAX_BYTES
        ))
    } else {
        Ok(())
    }
}

fn validate_project_configs_limit(limit: usize) -> Result<(), String> {
    if limit == 0 {
        return Err("limit must be positive".to_string());
    }
    if limit > config::PROJECT_CONFIGS_LIMIT_MAX {
        return Err(format!(
            "limit exceeds max value of {}",
            config::PROJECT_CONFIGS_LIMIT_MAX
        ));
    }
    Ok(())
}

fn validate_positive_id(id: i64, field_name: &str) -> Result<(), String> {
    if id > 0 {
        Ok(())
    } else {
        Err(format!("{field_name} must be positive"))
    }
}

pub fn get_session_meta(
    state: &AppState,
    session_id: String,
) -> Result<Option<db::SessionMetaRow>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_session_meta(&conn, &session_id).map_err(|e| e.to_string())
}

pub fn get_dream_queue(state: &AppState) -> Result<Vec<db::DreamQueueEntry>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_dream_queue(&conn).map_err(|e| e.to_string())
}

pub fn get_dream_state(state: &AppState, limit: usize) -> Result<Vec<db::DreamStateEntry>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_dream_state(&conn, limit).map_err(|e| e.to_string())
}

pub fn get_dream_runs(
    state: &AppState,
    project_path: Option<String>,
    limit: usize,
) -> Result<Vec<db::DreamRun>, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_dream_runs(&conn, project_path.as_deref(), limit)
}

pub fn get_dream_run_memory_changes(
    state: &AppState,
    run_id: i64,
    limit: usize,
) -> Result<db::DreamRunMemoryDetail, String> {
    let path = state.get_db_path()?;
    let conn = db::open_readonly(&path).map_err(|e| e.to_string())?;
    db::get_dream_run_memory_changes(&conn, run_id, limit)
}

fn missing_db_health() -> db::DbHealth {
    db::DbHealth {
        exists: false,
        path: "Not found".to_string(),
        size_bytes: 0,
        wal_size_bytes: 0,
        table_counts: Vec::new(),
    }
}

fn validate_content_size(content: &str) -> Result<(), String> {
    let byte_len = content.len();
    if byte_len <= SESSION_VIEWER_CONTENT_MAX_BYTES {
        Ok(())
    } else {
        Err(format!(
            "content exceeds max size of {} bytes",
            SESSION_VIEWER_CONTENT_MAX_BYTES
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn get_log_entries_from_path_returns_redacted_entries_without_raw() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("magic-context.log");
        let mut file = fs::File::create(&path).expect("create file");
        writeln!(
            file,
            "[2026-06-08T00:00:00Z] [magic-context][sess] Authorization: Bearer sk-secret cache.read=25 cache.write=75 tokens.input=100 /home/naadir/work"
        )
        .expect("write line");
        file.flush().expect("flush");

        let entries = get_log_entries_from_path(&path, 500);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.raw, None);
        assert_eq!(entry.cache_read, Some(25));
        assert_eq!(entry.cache_write, Some(75));
        assert_eq!(entry.hit_ratio, Some(0.25));
        assert!(!entry.message.contains("sk-secret"));
        assert!(!entry.message.contains("/home/naadir/work"));
        assert!(entry.message.contains("Bearer [REDACTED]"));
        assert!(entry.message.contains("~/work"));
    }

    #[test]
    fn get_log_entries_from_path_missing_file_returns_empty_vec() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("missing.log");
        let entries = get_log_entries_from_path(&path, 500);
        assert!(entries.is_empty());
    }

    #[test]
    fn get_log_entries_from_path_truncates_message_safely() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("magic-context.log");
        let long_value = format!(
            "{}🙂",
            "x".repeat(crate::log_parser::LOG_ENTRY_MESSAGE_MAX_BYTES + 32)
        );
        let mut file = fs::File::create(&path).expect("create file");
        writeln!(
            file,
            "[2026-06-08T00:00:00Z] [magic-context][sess] {long_value}"
        )
        .expect("write line");
        file.flush().expect("flush");

        let entries = get_log_entries_from_path(&path, 500);
        assert_eq!(entries.len(), 1);
        let message = &entries[0].message;
        assert!(message.len() <= crate::log_parser::LOG_ENTRY_MESSAGE_MAX_BYTES);
        assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    }
}
