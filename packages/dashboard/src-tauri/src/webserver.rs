use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::{config, db, services, AppState};

const DEFAULT_PORT: u16 = 1422;
const VITE_DEV_PORT: u16 = 1420;
const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]", "::1"];
const LOCAL_AUTH_TOKEN_HEADER: &str = "X-Magic-Context-Token";
const LOCAL_AUTH_TOKEN_ENV_VAR: &str = "MAGIC_CONTEXT_DASHBOARD_TOKEN";
const DIST_ENV_VAR: &str = "MAGIC_CONTEXT_DASHBOARD_DIST";
const GET_MEMORIES_LIMIT_MAX: i64 = 500;
const LIST_SESSIONS_LIMIT_MAX: u32 = 200;
const BULK_MEMORY_IDS_MAX: usize = 100;
const SUBAGENT_INVOCATIONS_LIMIT_MAX: usize = 200;
const SUBAGENT_TOTALS_LIMIT_MAX: usize = 100;
const PROJECT_KEY_FILES_LIMIT_MAX: usize = 25;
const COMPARTMENTS_LIMIT_MAX: usize = 200;
const DREAM_STATE_LIMIT_MAX: usize = 200;
const DREAM_RUNS_LIMIT_MAX: usize = 50;
const DREAM_MEMORY_CHANGES_LIMIT_MAX: usize = 200;
const SMART_NOTES_LIMIT_MAX: usize = 200;
const SESSION_MESSAGES_LIMIT_DEFAULT: usize = 1000;
const SESSION_MESSAGES_LIMIT_MAX: usize = 2000;
const SESSION_CACHE_EVENTS_LIMIT_DEFAULT: usize = 600;
const SESSION_CACHE_EVENTS_LIMIT_MAX: usize = 600;
const SESSION_CACHE_TARGET_TURNS_DEFAULT: usize = 200;
const SESSION_CACHE_TARGET_TURNS_MAX: usize = 200;
const GLOBAL_CACHE_EVENTS_LIMIT_DEFAULT: usize = 200;
const GLOBAL_CACHE_EVENTS_LIMIT_MAX: usize = 200;
const HIGH_VOLUME_READ_BODY_MAX_BYTES: usize = 8 * 1024;
const USER_MEMORIES_LIMIT_DEFAULT: usize = 200;
const USER_MEMORIES_LIMIT_MAX: usize = 500;
const USER_MEMORY_CANDIDATES_LIMIT_DEFAULT: usize = 100;
const USER_MEMORY_CANDIDATES_LIMIT_MAX: usize = 200;
const USER_MEMORY_CONTENT_MAX_BYTES: usize = 64 * 1024;
const USER_MEMORY_READ_BODY_MAX_BYTES: usize = 8 * 1024;
const USER_MEMORY_ID_BODY_MAX_BYTES: usize = 4 * 1024;
const USER_MEMORY_CONTENT_BODY_MAX_BYTES: usize = 72 * 1024;
const CONFIG_CONTENT_MAX_BYTES: usize = config::CONFIG_CONTENT_MAX_BYTES;
const CONFIG_WRITE_BODY_MAX_BYTES: usize = 512 * 1024;
const CONFIG_READ_BODY_MAX_BYTES: usize = 8 * 1024;
const PROJECT_PATH_MAX_BYTES: usize = config::PROJECT_PATH_MAX_BYTES;
const PROJECT_CONFIGS_LIMIT_DEFAULT: usize = config::PROJECT_CONFIGS_LIMIT_DEFAULT;
const PROJECT_CONFIGS_LIMIT_MAX: usize = config::PROJECT_CONFIGS_LIMIT_MAX;
const LOG_ENTRIES_READ_BODY_MAX_BYTES: usize = 4 * 1024;
const MODEL_DISCOVERY_READ_BODY_MAX_BYTES: usize = 2 * 1024;
const EMBEDDING_PROBE_BODY_MAX_BYTES: usize = 16 * 1024;
const EMBEDDING_ENDPOINT_MAX_BYTES: usize = 2048;
const EMBEDDING_MODEL_MAX_BYTES: usize = 512;
const EMBEDDING_API_KEY_MAX_BYTES: usize = 8192;
const EMBEDDING_OPTIONAL_FIELD_MAX_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandAccess {
    BasicRead,
    SensitiveRead,
    Write,
    SideEffect,
    Process,
    OutboundProbe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandHandler {
    GetDashboardSchemaWarning,
    GetDbHealth,
    GetProjects,
    GetMemories,
    GetMemoryStats,
    UpdateMemoryStatus,
    UpdateMemoryContent,
    DeleteMemory,
    BulkUpdateMemoryStatus,
    BulkDeleteMemory,
    GetSessions,
    ListSessions,
    ListSessionsPaged,
    GetSessionDetail,
    GetSessionMessages,
    GetSessionCacheEvents,
    GetSessionCacheEventsByTurns,
    GetCacheEventsFromDb,
    GetSubagentInvocations,
    GetSubagentTotalsBySubagent,
    GetProjectKeyFiles,
    GetCompartments,
    GetSmartNotes,
    UpdateSessionFact,
    DeleteSessionFact,
    UpdateNote,
    DeleteNote,
    DismissNote,
    GetSessionMeta,
    GetDreamQueue,
    GetDreamState,
    GetDreamRuns,
    GetDreamRunMemoryChanges,
    GetUserMemories,
    GetUserMemoryCandidates,
    DismissUserMemory,
    DeleteUserMemory,
    UpdateUserMemoryContent,
    DeleteUserMemoryCandidate,
    PromoteUserMemoryCandidate,
    GetConfig,
    SaveConfig,
    ReadPiConfig,
    WritePiConfig,
    GetProjectConfigs,
    SaveProjectConfig,
    GetLogEntries,
    GetAvailableModels,
    GetAvailablePiModels,
    TestEmbeddingEndpoint,
    #[cfg(test)]
    TestReadProbe,
    #[cfg(test)]
    TestSensitiveReadProbe,
    #[cfg(test)]
    TestWriteCommand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: &'static str,
    pub access: CommandAccess,
    pub handler: CommandHandler,
}

pub const COMMAND_ALLOWLIST: &[CommandSpec] = &[
    CommandSpec {
        name: "get_dashboard_schema_warning",
        access: CommandAccess::BasicRead,
        handler: CommandHandler::GetDashboardSchemaWarning,
    },
    CommandSpec {
        name: "get_db_health",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetDbHealth,
    },
    CommandSpec {
        name: "get_projects",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetProjects,
    },
    CommandSpec {
        name: "get_memories",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetMemories,
    },
    CommandSpec {
        name: "get_memory_stats",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetMemoryStats,
    },
    CommandSpec {
        name: "update_memory_status",
        access: CommandAccess::Write,
        handler: CommandHandler::UpdateMemoryStatus,
    },
    CommandSpec {
        name: "update_memory_content",
        access: CommandAccess::Write,
        handler: CommandHandler::UpdateMemoryContent,
    },
    CommandSpec {
        name: "delete_memory",
        access: CommandAccess::SideEffect,
        handler: CommandHandler::DeleteMemory,
    },
    CommandSpec {
        name: "bulk_update_memory_status",
        access: CommandAccess::Write,
        handler: CommandHandler::BulkUpdateMemoryStatus,
    },
    CommandSpec {
        name: "bulk_delete_memory",
        access: CommandAccess::SideEffect,
        handler: CommandHandler::BulkDeleteMemory,
    },
    CommandSpec {
        name: "get_sessions",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSessions,
    },
    CommandSpec {
        name: "list_sessions",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::ListSessions,
    },
    CommandSpec {
        name: "list_sessions_paged",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::ListSessionsPaged,
    },
    CommandSpec {
        name: "get_session_detail",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSessionDetail,
    },
    CommandSpec {
        name: "get_session_messages",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSessionMessages,
    },
    CommandSpec {
        name: "get_session_cache_events",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSessionCacheEvents,
    },
    CommandSpec {
        name: "get_session_cache_events_by_turns",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSessionCacheEventsByTurns,
    },
    CommandSpec {
        name: "get_cache_events_from_db",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetCacheEventsFromDb,
    },
    CommandSpec {
        name: "get_subagent_invocations",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSubagentInvocations,
    },
    CommandSpec {
        name: "get_subagent_totals_by_subagent",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSubagentTotalsBySubagent,
    },
    CommandSpec {
        name: "get_project_key_files",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetProjectKeyFiles,
    },
    CommandSpec {
        name: "get_compartments",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetCompartments,
    },
    CommandSpec {
        name: "get_smart_notes",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSmartNotes,
    },
    CommandSpec {
        name: "update_session_fact",
        access: CommandAccess::Write,
        handler: CommandHandler::UpdateSessionFact,
    },
    CommandSpec {
        name: "delete_session_fact",
        access: CommandAccess::SideEffect,
        handler: CommandHandler::DeleteSessionFact,
    },
    CommandSpec {
        name: "update_note",
        access: CommandAccess::Write,
        handler: CommandHandler::UpdateNote,
    },
    CommandSpec {
        name: "delete_note",
        access: CommandAccess::SideEffect,
        handler: CommandHandler::DeleteNote,
    },
    CommandSpec {
        name: "dismiss_note",
        access: CommandAccess::Write,
        handler: CommandHandler::DismissNote,
    },
    CommandSpec {
        name: "get_session_meta",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetSessionMeta,
    },
    // Dreamer read commands.
    CommandSpec {
        name: "get_dream_queue",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetDreamQueue,
    },
    CommandSpec {
        name: "get_dream_state",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetDreamState,
    },
    CommandSpec {
        name: "get_dream_runs",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetDreamRuns,
    },
    CommandSpec {
        name: "get_dream_run_memory_changes",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetDreamRunMemoryChanges,
    },
    CommandSpec {
        name: "get_user_memories",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetUserMemories,
    },
    CommandSpec {
        name: "get_user_memory_candidates",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetUserMemoryCandidates,
    },
    CommandSpec {
        name: "dismiss_user_memory",
        access: CommandAccess::Write,
        handler: CommandHandler::DismissUserMemory,
    },
    CommandSpec {
        name: "delete_user_memory",
        access: CommandAccess::SideEffect,
        handler: CommandHandler::DeleteUserMemory,
    },
    CommandSpec {
        name: "update_user_memory_content",
        access: CommandAccess::Write,
        handler: CommandHandler::UpdateUserMemoryContent,
    },
    CommandSpec {
        name: "delete_user_memory_candidate",
        access: CommandAccess::SideEffect,
        handler: CommandHandler::DeleteUserMemoryCandidate,
    },
    CommandSpec {
        name: "promote_user_memory_candidate",
        access: CommandAccess::SideEffect,
        handler: CommandHandler::PromoteUserMemoryCandidate,
    },
    CommandSpec {
        name: "get_config",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetConfig,
    },
    CommandSpec {
        name: "save_config",
        access: CommandAccess::Write,
        handler: CommandHandler::SaveConfig,
    },
    CommandSpec {
        name: "read_pi_config",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::ReadPiConfig,
    },
    CommandSpec {
        name: "write_pi_config",
        access: CommandAccess::Write,
        handler: CommandHandler::WritePiConfig,
    },
    CommandSpec {
        name: "get_project_configs",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetProjectConfigs,
    },
    CommandSpec {
        name: "save_project_config",
        access: CommandAccess::Write,
        handler: CommandHandler::SaveProjectConfig,
    },
    CommandSpec {
        name: "get_log_entries",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::GetLogEntries,
    },
    CommandSpec {
        name: "get_available_models",
        access: CommandAccess::Process,
        handler: CommandHandler::GetAvailableModels,
    },
    CommandSpec {
        name: "get_available_pi_models",
        access: CommandAccess::Process,
        handler: CommandHandler::GetAvailablePiModels,
    },
    CommandSpec {
        name: "test_embedding_endpoint",
        access: CommandAccess::OutboundProbe,
        handler: CommandHandler::TestEmbeddingEndpoint,
    },
];

#[cfg(test)]
const TEST_COMMAND_ALLOWLIST: &[CommandSpec] = &[
    CommandSpec {
        name: "test_read_probe",
        access: CommandAccess::BasicRead,
        handler: CommandHandler::TestReadProbe,
    },
    CommandSpec {
        name: "test_sensitive_read_probe",
        access: CommandAccess::SensitiveRead,
        handler: CommandHandler::TestSensitiveReadProbe,
    },
    CommandSpec {
        name: "test_write_command",
        access: CommandAccess::Write,
        handler: CommandHandler::TestWriteCommand,
    },
];

#[derive(Clone)]
pub struct WebServerState {
    app_state: Arc<AppState>,
    server_port: u16,
    static_assets: StaticAssets,
    local_auth_token: String,
}

#[derive(Clone, Debug)]
struct StaticAssets {
    dist_dir: Option<PathBuf>,
    index_file: Option<PathBuf>,
    missing_message: Arc<String>,
}

#[derive(Debug, Serialize)]
struct BootstrapPayload<'a> {
    #[serde(rename = "localToken")]
    local_token: &'a str,
}

#[derive(Debug, Serialize)]
struct SuccessEnvelope<T> {
    ok: bool,
    data: T,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    ok: bool,
    error: String,
}

#[derive(Debug, Deserialize, Default)]
struct GetMemoriesRequest {
    project: Option<String>,
    workspace_id: Option<i64>,
    status: Option<String>,
    category: Option<String>,
    search: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct GetMemoryStatsRequest {
    project: Option<String>,
    workspace_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct UpdateMemoryStatusRequest {
    #[serde(alias = "memoryId")]
    memory_id: i64,
    status: String,
}

#[derive(Debug, Deserialize)]
struct UpdateMemoryContentRequest {
    #[serde(alias = "memoryId")]
    memory_id: i64,
    content: String,
}

#[derive(Debug, Deserialize)]
struct DeleteMemoryRequest {
    #[serde(alias = "memoryId")]
    memory_id: i64,
}

#[derive(Debug, Deserialize)]
struct BulkUpdateMemoryStatusRequest {
    #[serde(alias = "memoryIds")]
    memory_ids: Vec<i64>,
    status: String,
}

#[derive(Debug, Deserialize)]
struct BulkDeleteMemoryRequest {
    #[serde(alias = "memoryIds")]
    memory_ids: Vec<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct SessionFilterRequest {
    filter: Option<db::SessionFilter>,
}

#[derive(Debug, Deserialize)]
struct GetSessionDetailRequest {
    harness: db::Harness,
    #[serde(alias = "sessionId")]
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct GetSessionMessagesRequest {
    harness: db::Harness,
    #[serde(alias = "sessionId")]
    session_id: String,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct GetLogEntriesRequest {
    #[serde(rename = "maxLines")]
    max_lines: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GetSessionCacheEventsRequest {
    harness: db::Harness,
    #[serde(alias = "sessionId")]
    session_id: String,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GetSessionCacheEventsByTurnsRequest {
    harness: db::Harness,
    #[serde(alias = "sessionId")]
    session_id: String,
    #[serde(alias = "targetTurns")]
    target_turns: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct GetCacheEventsFromDbRequest {
    limit: Option<i64>,
    #[serde(alias = "sinceTimestamp")]
    since_timestamp: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SessionIdRequest {
    #[serde(alias = "sessionId")]
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct ProjectPathRequest {
    #[serde(alias = "projectPath")]
    project_path: String,
}

#[derive(Debug, Deserialize)]
struct FactIdRequest {
    #[serde(alias = "factId")]
    fact_id: i64,
}

#[derive(Debug, Deserialize)]
struct UpdateSessionFactRequest {
    #[serde(alias = "factId")]
    fact_id: i64,
    content: String,
}

#[derive(Debug, Deserialize)]
struct NoteIdRequest {
    #[serde(alias = "noteId")]
    note_id: i64,
}

#[derive(Debug, Deserialize)]
struct UpdateNoteRequest {
    #[serde(alias = "noteId")]
    note_id: i64,
    content: String,
}

#[derive(Debug, Deserialize, Default)]
struct GetDreamRunsRequest {
    #[serde(alias = "projectPath")]
    project_path: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GetDreamRunMemoryChangesRequest {
    #[serde(alias = "runId")]
    run_id: i64,
}

#[derive(Debug, Deserialize, Default)]
struct GetUserMemoriesRequest {
    status: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct GetUserMemoryCandidatesRequest {
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct UserMemoryIdRequest {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct UpdateUserMemoryContentRequest {
    id: i64,
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetConfigRequest {
    source: String,
    #[serde(alias = "projectPath")]
    project_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveConfigRequest {
    source: String,
    content: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct EmptyConfigReadRequest {}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct EmptyModelDiscoveryRequest {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TestEmbeddingEndpointRequest {
    endpoint: String,
    model: String,
    api_key: Option<String>,
    input_type: Option<String>,
    truncate: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct GetProjectConfigsRequest {
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WritePiConfigRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveProjectConfigRequest {
    #[serde(alias = "projectPath")]
    project_path: String,
    content: String,
}

enum StaticTarget {
    File(PathBuf),
    InjectedIndex(PathBuf),
    MissingAssets,
    NotFound,
}

pub async fn serve_from_env() -> Result<(), Box<dyn std::error::Error>> {
    let port = read_port_from_env()?;
    let listener = bind_listener(port).await?;
    let static_assets = resolve_static_assets();
    let local_auth_token = read_or_generate_local_auth_token();

    if let Some(dist_dir) = &static_assets.dist_dir {
        eprintln!(
            "[dashboard-webserver] serving dashboard assets from {}",
            dist_dir.display()
        );
    } else {
        eprintln!(
            "[dashboard-webserver] dashboard dist missing: {}",
            static_assets.missing_message
        );
    }

    let state = WebServerState {
        app_state: Arc::new(AppState::new()),
        server_port: port,
        static_assets,
        local_auth_token,
    };
    let app = build_router(state);

    eprintln!("[dashboard-webserver] listening on http://127.0.0.1:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn read_or_generate_local_auth_token() -> String {
    match std::env::var(LOCAL_AUTH_TOKEN_ENV_VAR) {
        Ok(token) if !token.trim().is_empty() => token,
        _ => generate_local_auth_token(),
    }
}

fn generate_local_auth_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn build_router(state: WebServerState) -> Router {
    let api_router = Router::new()
        .route("/{command}", any(api_command_entry))
        .fallback(any(api_not_found));

    Router::new()
        .nest("/api", api_router)
        .fallback(get(serve_static))
        .with_state(state)
}

fn read_port_from_env() -> Result<u16, Box<dyn std::error::Error>> {
    match std::env::var("MAGIC_CONTEXT_DASHBOARD_PORT") {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|_| format!("invalid MAGIC_CONTEXT_DASHBOARD_PORT: {value}").into()),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_PORT),
        Err(err) => Err(err.into()),
    }
}

async fn bind_listener(port: u16) -> Result<tokio::net::TcpListener, std::io::Error> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tokio::net::TcpListener::bind(addr).await
}

fn resolve_static_assets() -> StaticAssets {
    if let Ok(raw_path) = std::env::var(DIST_ENV_VAR) {
        let dist_dir = PathBuf::from(raw_path.trim());
        return StaticAssets::from_candidate(dist_dir, format!("resolved from {DIST_ENV_VAR}"));
    }

    let candidates = dist_candidates();
    for candidate in &candidates {
        if candidate.is_dir() {
            return StaticAssets::from_candidate(
                candidate.clone(),
                "auto-discovered dist directory".into(),
            );
        }
    }

    let tried_paths = candidates
        .into_iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    StaticAssets {
        dist_dir: None,
        index_file: None,
        missing_message: Arc::new(format!(
            "dashboard build output not found. Run `bun run build` in packages/dashboard or set {DIST_ENV_VAR}. Tried: {tried_paths}"
        )),
    }
}

fn dist_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join("dist"));
        candidates.push(current_dir.join("../dist"));
        candidates.push(current_dir.join("packages/dashboard/dist"));
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist"));
    dedupe_paths(candidates)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique = Vec::new();
    for path in paths {
        if !unique.iter().any(|existing| existing == &path) {
            unique.push(path);
        }
    }
    unique
}

impl StaticAssets {
    fn from_candidate(dist_dir: PathBuf, source: String) -> Self {
        let index_file = dist_dir.join("index.html");
        let index_exists = index_file.is_file();
        let missing_message = if index_exists {
            format!(
                "dashboard assets ready from {} ({source})",
                dist_dir.display()
            )
        } else {
            format!(
                "dashboard dist found at {} ({source}) but index.html is missing. Run `bun run build` in packages/dashboard.",
                dist_dir.display()
            )
        };

        Self {
            dist_dir: Some(dist_dir),
            index_file: index_exists.then_some(index_file),
            missing_message: Arc::new(missing_message),
        }
    }
}

async fn api_command_entry(
    method: axum::http::Method,
    state: State<WebServerState>,
    command: Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != axum::http::Method::POST {
        return api_not_found().await;
    }

    dispatch_command(state, command, headers, body).await
}

async fn dispatch_command(
    State(state): State<WebServerState>,
    Path(command): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = validate_api_request(&headers, state.server_port) {
        return response;
    }

    let Some(spec) = find_command_spec(&command) else {
        return error_response(StatusCode::NOT_FOUND, format!("unknown command: {command}"));
    };

    if let Err(response) = enforce_command_access(spec, &headers, &state.local_auth_token) {
        return response;
    }

    dispatch_spec(spec, state, &body).await
}

async fn api_not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "unknown API route")
}

async fn serve_static(
    State(state): State<WebServerState>,
    request: Request<axum::body::Body>,
) -> Response {
    let request_path = request.uri().path().trim_start_matches('/').to_string();

    match resolve_static_target(&state.static_assets, &request_path) {
        StaticTarget::File(file_path) => serve_file(request, file_path).await,
        StaticTarget::InjectedIndex(index_file) => {
            serve_index_with_bootstrap(index_file, &state.local_auth_token).await
        }
        StaticTarget::MissingAssets => missing_dist_response(&state.static_assets.missing_message),
        StaticTarget::NotFound => error_response(
            StatusCode::NOT_FOUND,
            format!("static asset not found: /{request_path}"),
        ),
    }
}

fn resolve_static_target(static_assets: &StaticAssets, request_path: &str) -> StaticTarget {
    let Some(dist_dir) = &static_assets.dist_dir else {
        return StaticTarget::MissingAssets;
    };

    let Some(index_file) = &static_assets.index_file else {
        return StaticTarget::MissingAssets;
    };

    if request_path.is_empty() {
        return StaticTarget::InjectedIndex(index_file.clone());
    }

    if let Some(candidate) = sanitize_static_path(dist_dir, request_path) {
        if candidate.is_file() {
            return StaticTarget::File(candidate);
        }

        if candidate.is_dir() {
            let nested_index = candidate.join("index.html");
            if nested_index.is_file() {
                return StaticTarget::File(nested_index);
            }
        }
    }

    if path_looks_like_asset(request_path) {
        StaticTarget::NotFound
    } else {
        StaticTarget::InjectedIndex(index_file.clone())
    }
}

fn sanitize_static_path(dist_dir: &FsPath, request_path: &str) -> Option<PathBuf> {
    let mut candidate = PathBuf::from(dist_dir);

    for component in FsPath::new(request_path).components() {
        match component {
            std::path::Component::Normal(segment) => candidate.push(segment),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }

    Some(candidate)
}

fn path_looks_like_asset(request_path: &str) -> bool {
    FsPath::new(request_path)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains('.'))
}

async fn serve_file(request: Request<axum::body::Body>, file_path: PathBuf) -> Response {
    match ServeFile::new(file_path).oneshot(request).await {
        Ok(response) => response.into_response(),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serve static asset: {error}"),
        ),
    }
}

async fn serve_index_with_bootstrap(index_file: PathBuf, local_auth_token: &str) -> Response {
    match tokio::fs::read_to_string(&index_file).await {
        Ok(html) => match inject_bootstrap_token(&html, local_auth_token) {
            Ok(injected_html) => {
                let mut response = Html(injected_html).into_response();
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                response
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
        },
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read index.html: {error}"),
        ),
    }
}

fn inject_bootstrap_token(html: &str, local_auth_token: &str) -> Result<String, String> {
    let bootstrap_json = serde_json::to_string(&BootstrapPayload {
        local_token: local_auth_token,
    })
    .map_err(|error| format!("failed to serialize bootstrap payload: {error}"))?;
    let bootstrap_tag = format!(
        r#"<script id="magic-context-bootstrap" type="application/json">{bootstrap_json}</script>"#
    );

    if let Some(index) = html.find("</head>") {
        let mut output = String::with_capacity(html.len() + bootstrap_tag.len());
        output.push_str(&html[..index]);
        output.push_str(&bootstrap_tag);
        output.push_str(&html[index..]);
        return Ok(output);
    }

    if let Some(index) = html.find("</body>") {
        let mut output = String::with_capacity(html.len() + bootstrap_tag.len());
        output.push_str(&html[..index]);
        output.push_str(&bootstrap_tag);
        output.push_str(&html[index..]);
        return Ok(output);
    }

    Ok(format!("{html}{bootstrap_tag}"))
}

fn missing_dist_response(message: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Dashboard build missing</title></head><body><h1>Dashboard build missing</h1><p>{message}</p></body></html>"
        )),
    )
        .into_response()
}

#[cfg(not(test))]
fn find_command_spec(command: &str) -> Option<CommandSpec> {
    COMMAND_ALLOWLIST
        .iter()
        .find(|spec| spec.name == command)
        .copied()
}

#[cfg(test)]
fn find_command_spec(command: &str) -> Option<CommandSpec> {
    COMMAND_ALLOWLIST
        .iter()
        .chain(TEST_COMMAND_ALLOWLIST.iter())
        .find(|spec| spec.name == command)
        .copied()
}

fn requires_local_auth(access: CommandAccess) -> bool {
    matches!(
        access,
        CommandAccess::SensitiveRead
            | CommandAccess::Write
            | CommandAccess::SideEffect
            | CommandAccess::Process
            | CommandAccess::OutboundProbe
    )
}

fn enforce_command_access(
    spec: CommandSpec,
    headers: &HeaderMap,
    local_auth_token: &str,
) -> Result<(), Response> {
    if !requires_local_auth(spec.access) {
        return Ok(());
    }

    require_local_auth_token(headers, local_auth_token)
}

fn require_local_auth_token(headers: &HeaderMap, local_auth_token: &str) -> Result<(), Response> {
    let provided = headers
        .get(LOCAL_AUTH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    match provided {
        Some(token) if !token.is_empty() && token == local_auth_token => Ok(()),
        _ => Err(error_response(
            StatusCode::FORBIDDEN,
            format!("missing or invalid {LOCAL_AUTH_TOKEN_HEADER} header"),
        )),
    }
}

async fn dispatch_spec(spec: CommandSpec, state: WebServerState, body: &[u8]) -> Response {
    match spec.handler {
        CommandHandler::GetDashboardSchemaWarning => {
            handle_get_dashboard_schema_warning(state).await
        }
        CommandHandler::GetDbHealth => handle_get_db_health(state).await,
        CommandHandler::GetProjects => handle_get_projects(state).await,
        CommandHandler::GetMemories => handle_get_memories(state, body).await,
        CommandHandler::GetMemoryStats => handle_get_memory_stats(state, body).await,
        CommandHandler::UpdateMemoryStatus => handle_update_memory_status(state, body).await,
        CommandHandler::UpdateMemoryContent => handle_update_memory_content(state, body).await,
        CommandHandler::DeleteMemory => handle_delete_memory(state, body).await,
        CommandHandler::BulkUpdateMemoryStatus => {
            handle_bulk_update_memory_status(state, body).await
        }
        CommandHandler::BulkDeleteMemory => handle_bulk_delete_memory(state, body).await,
        CommandHandler::GetSessions => handle_get_sessions(state).await,
        CommandHandler::ListSessions => handle_list_sessions(state, body).await,
        CommandHandler::ListSessionsPaged => handle_list_sessions_paged(state, body).await,
        CommandHandler::GetSessionDetail => handle_get_session_detail(state, body).await,
        CommandHandler::GetSessionMessages => handle_get_session_messages(state, body).await,
        CommandHandler::GetSessionCacheEvents => handle_get_session_cache_events(state, body).await,
        CommandHandler::GetSessionCacheEventsByTurns => {
            handle_get_session_cache_events_by_turns(state, body).await
        }
        CommandHandler::GetCacheEventsFromDb => handle_get_cache_events_from_db(state, body).await,
        CommandHandler::GetSubagentInvocations => {
            handle_get_subagent_invocations(state, body).await
        }
        CommandHandler::GetSubagentTotalsBySubagent => {
            handle_get_subagent_totals_by_subagent(state, body).await
        }
        CommandHandler::GetProjectKeyFiles => handle_get_project_key_files(state, body).await,
        CommandHandler::GetCompartments => handle_get_compartments(state, body).await,
        CommandHandler::GetSmartNotes => handle_get_smart_notes(state, body).await,
        CommandHandler::UpdateSessionFact => handle_update_session_fact(state, body).await,
        CommandHandler::DeleteSessionFact => handle_delete_session_fact(state, body).await,
        CommandHandler::UpdateNote => handle_update_note(state, body).await,
        CommandHandler::DeleteNote => handle_delete_note(state, body).await,
        CommandHandler::DismissNote => handle_dismiss_note(state, body).await,
        CommandHandler::GetSessionMeta => handle_get_session_meta(state, body).await,
        CommandHandler::GetDreamQueue => handle_get_dream_queue(state).await,
        CommandHandler::GetDreamState => handle_get_dream_state(state).await,
        CommandHandler::GetDreamRuns => handle_get_dream_runs(state, body).await,
        CommandHandler::GetDreamRunMemoryChanges => {
            handle_get_dream_run_memory_changes(state, body).await
        }
        CommandHandler::GetUserMemories => handle_get_user_memories(state, body).await,
        CommandHandler::GetUserMemoryCandidates => {
            handle_get_user_memory_candidates(state, body).await
        }
        CommandHandler::DismissUserMemory => handle_dismiss_user_memory(state, body).await,
        CommandHandler::DeleteUserMemory => handle_delete_user_memory(state, body).await,
        CommandHandler::UpdateUserMemoryContent => {
            handle_update_user_memory_content(state, body).await
        }
        CommandHandler::DeleteUserMemoryCandidate => {
            handle_delete_user_memory_candidate(state, body).await
        }
        CommandHandler::PromoteUserMemoryCandidate => {
            handle_promote_user_memory_candidate(state, body).await
        }
        CommandHandler::GetConfig => handle_get_config(state, body).await,
        CommandHandler::SaveConfig => handle_save_config(state, body).await,
        CommandHandler::ReadPiConfig => handle_read_pi_config(state, body).await,
        CommandHandler::WritePiConfig => handle_write_pi_config(state, body).await,
        CommandHandler::GetProjectConfigs => handle_get_project_configs(state, body).await,
        CommandHandler::SaveProjectConfig => handle_save_project_config(state, body).await,
        CommandHandler::GetLogEntries => handle_get_log_entries(state, body).await,
        CommandHandler::GetAvailableModels => handle_get_available_models(state, body).await,
        CommandHandler::GetAvailablePiModels => handle_get_available_pi_models(state, body).await,
        CommandHandler::TestEmbeddingEndpoint => handle_test_embedding_endpoint(state, body).await,
        #[cfg(test)]
        CommandHandler::TestReadProbe => handle_test_read_probe().await,
        #[cfg(test)]
        CommandHandler::TestSensitiveReadProbe => handle_test_sensitive_read_probe().await,
        #[cfg(test)]
        CommandHandler::TestWriteCommand => handle_test_write_command().await,
    }
}

async fn handle_get_dashboard_schema_warning(state: WebServerState) -> Response {
    success_response(services::get_dashboard_schema_warning(&state.app_state))
}

async fn handle_get_db_health(state: WebServerState) -> Response {
    run_blocking_read(move || Ok(services::get_db_health(&state.app_state))).await
}

async fn handle_get_projects(state: WebServerState) -> Response {
    run_blocking_read(move || services::get_projects(&state.app_state)).await
}

async fn handle_get_memories(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_json_body::<GetMemoriesRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let limit = clamp_get_memories_limit(request.limit);

    run_blocking_read(move || {
        services::get_memories(
            &state.app_state,
            request.project,
            request.workspace_id,
            request.status,
            request.category,
            request.search,
            Some(limit),
            request.offset,
        )
    })
    .await
}

async fn handle_get_memory_stats(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_json_body::<GetMemoryStatsRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_memory_stats(&state.app_state, request.project, request.workspace_id)
    })
    .await
}

async fn handle_update_memory_status(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<UpdateMemoryStatusRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_write(move || {
        services::update_memory_status(&state.app_state, request.memory_id, request.status)
    })
    .await
}

async fn handle_update_memory_content(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<UpdateMemoryContentRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_write(move || {
        services::update_memory_content(&state.app_state, request.memory_id, request.content)
    })
    .await
}

async fn handle_delete_memory(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<DeleteMemoryRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_write(move || services::delete_memory(&state.app_state, request.memory_id)).await
}

async fn handle_bulk_update_memory_status(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<BulkUpdateMemoryStatusRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request.memory_ids.len() > BULK_MEMORY_IDS_MAX {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("memoryIds exceeds max batch size of {BULK_MEMORY_IDS_MAX}"),
        );
    }

    run_blocking_write(move || {
        services::bulk_update_memory_status(&state.app_state, request.memory_ids, request.status)
    })
    .await
}

async fn handle_bulk_delete_memory(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<BulkDeleteMemoryRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request.memory_ids.len() > BULK_MEMORY_IDS_MAX {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("memoryIds exceeds max batch size of {BULK_MEMORY_IDS_MAX}"),
        );
    }

    run_blocking_write(move || services::bulk_delete_memory(&state.app_state, request.memory_ids))
        .await
}

async fn handle_get_sessions(state: WebServerState) -> Response {
    run_blocking_read(move || services::get_sessions(&state.app_state)).await
}

async fn handle_list_sessions(_state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_json_body::<SessionFilterRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || Ok(services::list_sessions(request.filter))).await
}

async fn handle_list_sessions_paged(_state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_json_body::<SessionFilterRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let filter = clamp_session_filter_limit(request.filter);

    run_blocking_read(move || Ok(services::list_sessions_paged(filter))).await
}

async fn handle_get_session_detail(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<GetSessionDetailRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    let session_id = match validate_session_id(request.session_id) {
        Ok(session_id) => session_id,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_session_detail(&state.app_state, request.harness, session_id)
    })
    .await
}

async fn handle_get_session_messages(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        HIGH_VOLUME_READ_BODY_MAX_BYTES,
        "get_session_messages",
    ) {
        return response;
    }
    let request = match parse_required_json_body::<GetSessionMessagesRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let session_id = match validate_session_id(request.session_id) {
        Ok(session_id) => session_id,
        Err(response) => return response,
    };
    let limit = match validate_positive_limit_or_default(
        request.limit,
        "limit",
        SESSION_MESSAGES_LIMIT_DEFAULT,
        SESSION_MESSAGES_LIMIT_MAX,
    ) {
        Ok(limit) => limit,
        Err(response) => return response,
    };

    run_blocking_read(move || services::get_session_messages(request.harness, session_id, limit))
        .await
}

async fn handle_get_session_cache_events(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        HIGH_VOLUME_READ_BODY_MAX_BYTES,
        "get_session_cache_events",
    ) {
        return response;
    }
    let request = match parse_required_json_body::<GetSessionCacheEventsRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let session_id = match validate_session_id(request.session_id) {
        Ok(session_id) => session_id,
        Err(response) => return response,
    };
    let limit = match request.limit {
        Some(value) => {
            match validate_positive_limit_value(value, "limit", SESSION_CACHE_EVENTS_LIMIT_MAX) {
                Ok(limit) => limit,
                Err(response) => return response,
            }
        }
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "limit is required for get_session_cache_events browser reads (suggested {SESSION_CACHE_EVENTS_LIMIT_DEFAULT}, max {SESSION_CACHE_EVENTS_LIMIT_MAX})"
                ),
            )
        }
    };

    run_blocking_read(move || {
        services::get_session_cache_events(request.harness, session_id, limit)
    })
    .await
}

async fn handle_get_session_cache_events_by_turns(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        HIGH_VOLUME_READ_BODY_MAX_BYTES,
        "get_session_cache_events_by_turns",
    ) {
        return response;
    }
    let request = match parse_required_json_body::<GetSessionCacheEventsByTurnsRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let session_id = match validate_session_id(request.session_id) {
        Ok(session_id) => session_id,
        Err(response) => return response,
    };
    let target_turns = match validate_positive_limit_or_default(
        request.target_turns,
        "targetTurns",
        SESSION_CACHE_TARGET_TURNS_DEFAULT,
        SESSION_CACHE_TARGET_TURNS_MAX,
    ) {
        Ok(target_turns) => target_turns,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_session_cache_events_by_turns(request.harness, session_id, target_turns)
    })
    .await
}

async fn handle_get_cache_events_from_db(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        HIGH_VOLUME_READ_BODY_MAX_BYTES,
        "get_cache_events_from_db",
    ) {
        return response;
    }
    let request = match parse_json_body::<GetCacheEventsFromDbRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let limit = match validate_positive_limit_or_default(
        request.limit,
        "limit",
        GLOBAL_CACHE_EVENTS_LIMIT_DEFAULT,
        GLOBAL_CACHE_EVENTS_LIMIT_MAX,
    ) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let since_timestamp =
        match validate_optional_non_negative_i64(request.since_timestamp, "sinceTimestamp") {
            Ok(value) => value,
            Err(response) => return response,
        };
    run_blocking_read(move || services::get_cache_events_from_db(limit, since_timestamp)).await
}

async fn handle_get_subagent_invocations(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<SessionIdRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_subagent_invocations(
            &state.app_state,
            request.session_id,
            SUBAGENT_INVOCATIONS_LIMIT_MAX,
        )
    })
    .await
}

async fn handle_get_subagent_totals_by_subagent(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<SessionIdRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_subagent_totals_by_subagent(
            &state.app_state,
            request.session_id,
            SUBAGENT_TOTALS_LIMIT_MAX,
        )
    })
    .await
}

async fn handle_get_project_key_files(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<ProjectPathRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_project_key_files(
            &state.app_state,
            request.project_path,
            PROJECT_KEY_FILES_LIMIT_MAX,
        )
    })
    .await
}

async fn handle_get_compartments(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<SessionIdRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_compartments(&state.app_state, request.session_id, COMPARTMENTS_LIMIT_MAX)
    })
    .await
}

async fn handle_get_smart_notes(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<ProjectPathRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_smart_notes(
            &state.app_state,
            request.project_path,
            SMART_NOTES_LIMIT_MAX,
        )
    })
    .await
}

async fn handle_update_session_fact(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<UpdateSessionFactRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_positive_id(request.fact_id, "factId") {
        return response;
    }
    if let Err(response) = validate_content_size(&request.content) {
        return response;
    }

    run_blocking_write(move || {
        services::update_session_fact(&state.app_state, request.fact_id, request.content)
    })
    .await
}

async fn handle_delete_session_fact(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<FactIdRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_positive_id(request.fact_id, "factId") {
        return response;
    }

    run_blocking_write(move || services::delete_session_fact(&state.app_state, request.fact_id))
        .await
}

async fn handle_update_note(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<UpdateNoteRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_positive_id(request.note_id, "noteId") {
        return response;
    }
    if let Err(response) = validate_content_size(&request.content) {
        return response;
    }

    run_blocking_write(move || {
        services::update_note(&state.app_state, request.note_id, request.content)
    })
    .await
}

async fn handle_delete_note(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<NoteIdRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_positive_id(request.note_id, "noteId") {
        return response;
    }

    run_blocking_write(move || services::delete_note(&state.app_state, request.note_id)).await
}

async fn handle_dismiss_note(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<NoteIdRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_positive_id(request.note_id, "noteId") {
        return response;
    }

    run_blocking_write(move || services::dismiss_note(&state.app_state, request.note_id)).await
}

async fn handle_get_session_meta(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<SessionIdRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || services::get_session_meta(&state.app_state, request.session_id))
        .await
}

async fn handle_get_dream_queue(state: WebServerState) -> Response {
    run_blocking_read(move || services::get_dream_queue(&state.app_state)).await
}

async fn handle_get_dream_state(state: WebServerState) -> Response {
    run_blocking_read(move || services::get_dream_state(&state.app_state, DREAM_STATE_LIMIT_MAX))
        .await
}

async fn handle_get_dream_runs(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_json_body::<GetDreamRunsRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let limit = clamp_positive_limit(request.limit, 20, DREAM_RUNS_LIMIT_MAX);

    run_blocking_read(move || {
        services::get_dream_runs(&state.app_state, request.project_path, limit)
    })
    .await
}

async fn handle_get_dream_run_memory_changes(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_required_json_body::<GetDreamRunMemoryChangesRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_read(move || {
        services::get_dream_run_memory_changes(
            &state.app_state,
            request.run_id,
            DREAM_MEMORY_CHANGES_LIMIT_MAX,
        )
    })
    .await
}

async fn handle_get_user_memories(state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) =
        validate_body_size(body, USER_MEMORY_READ_BODY_MAX_BYTES, "get_user_memories")
    {
        return response;
    }
    let request = match parse_json_body::<GetUserMemoriesRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let status = match validate_user_memory_status(request.status) {
        Ok(status) => status,
        Err(response) => return response,
    };
    let limit = match validate_positive_limit_or_default(
        request.limit,
        "limit",
        USER_MEMORIES_LIMIT_DEFAULT,
        USER_MEMORIES_LIMIT_MAX,
    ) {
        Ok(limit) => limit,
        Err(response) => return response,
    };

    run_blocking_read(move || services::get_user_memories(&state.app_state, status, limit)).await
}

async fn handle_get_user_memory_candidates(state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        USER_MEMORY_READ_BODY_MAX_BYTES,
        "get_user_memory_candidates",
    ) {
        return response;
    }
    let request = match parse_json_body::<GetUserMemoryCandidatesRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let limit = match validate_positive_limit_or_default(
        request.limit,
        "limit",
        USER_MEMORY_CANDIDATES_LIMIT_DEFAULT,
        USER_MEMORY_CANDIDATES_LIMIT_MAX,
    ) {
        Ok(limit) => limit,
        Err(response) => return response,
    };

    run_blocking_read(move || services::get_user_memory_candidates(&state.app_state, limit)).await
}

async fn handle_dismiss_user_memory(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_user_memory_id_request(body, "dismiss_user_memory") {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_write(move || services::dismiss_user_memory(&state.app_state, request.id)).await
}

async fn handle_delete_user_memory(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_user_memory_id_request(body, "delete_user_memory") {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_write(move || services::delete_user_memory(&state.app_state, request.id)).await
}

async fn handle_update_user_memory_content(state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        USER_MEMORY_CONTENT_BODY_MAX_BYTES,
        "update_user_memory_content",
    ) {
        return response;
    }
    let request = match parse_required_json_body::<UpdateUserMemoryContentRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_positive_id(request.id, "id") {
        return response;
    }
    if let Err(response) = validate_user_memory_content(&request.content) {
        return response;
    }

    run_blocking_write(move || {
        services::update_user_memory_content(&state.app_state, request.id, request.content)
    })
    .await
}

async fn handle_delete_user_memory_candidate(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_user_memory_id_request(body, "delete_user_memory_candidate") {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_write(move || services::delete_user_memory_candidate(&state.app_state, request.id))
        .await
}

async fn handle_promote_user_memory_candidate(state: WebServerState, body: &[u8]) -> Response {
    let request = match parse_user_memory_id_request(body, "promote_user_memory_candidate") {
        Ok(request) => request,
        Err(response) => return response,
    };

    run_blocking_write(move || {
        services::promote_user_memory_candidate(&state.app_state, request.id)
    })
    .await
}

async fn handle_get_config(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(body, CONFIG_READ_BODY_MAX_BYTES, "get_config") {
        return response;
    }
    let request = match parse_required_json_body::<GetConfigRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let project_path = match validate_project_path_option(request.project_path) {
        Ok(project_path) => project_path,
        Err(response) => return response,
    };

    run_blocking_read(move || services::get_config(request.source, project_path)).await
}

async fn handle_save_config(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(body, CONFIG_WRITE_BODY_MAX_BYTES, "save_config") {
        return response;
    }
    let request = match parse_required_json_body::<SaveConfigRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_config_content(&request.content) {
        return response;
    }

    run_blocking_write(move || services::save_config(request.source, request.content)).await
}

async fn handle_read_pi_config(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(body, CONFIG_READ_BODY_MAX_BYTES, "read_pi_config") {
        return response;
    }
    if let Err(response) = parse_json_body::<EmptyConfigReadRequest>(body) {
        return response;
    }

    run_blocking_read(move || services::read_pi_config()).await
}

async fn handle_write_pi_config(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(body, CONFIG_WRITE_BODY_MAX_BYTES, "write_pi_config")
    {
        return response;
    }
    let request = match parse_required_json_body::<WritePiConfigRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_config_content(&request.content) {
        return response;
    }

    run_blocking_write(move || services::write_pi_config(request.content)).await
}

async fn handle_get_project_configs(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) =
        validate_body_size(body, CONFIG_READ_BODY_MAX_BYTES, "get_project_configs")
    {
        return response;
    }
    let request = match parse_json_body::<GetProjectConfigsRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let limit = match validate_positive_limit_or_default(
        request.limit,
        "limit",
        PROJECT_CONFIGS_LIMIT_DEFAULT,
        PROJECT_CONFIGS_LIMIT_MAX,
    ) {
        Ok(limit) => limit,
        Err(response) => return response,
    };

    run_blocking_read(move || services::get_project_configs(limit)).await
}

async fn handle_save_project_config(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) =
        validate_body_size(body, CONFIG_WRITE_BODY_MAX_BYTES, "save_project_config")
    {
        return response;
    }
    let request = match parse_required_json_body::<SaveProjectConfigRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(response) = validate_project_path(&request.project_path) {
        return response;
    }
    if let Err(response) = validate_config_content(&request.content) {
        return response;
    }

    run_blocking_write(move || services::save_project_config(request.project_path, request.content))
        .await
}

async fn handle_get_log_entries(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) =
        validate_body_size(body, LOG_ENTRIES_READ_BODY_MAX_BYTES, "get_log_entries")
    {
        return response;
    }
    let request = match parse_json_body::<GetLogEntriesRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let max_lines = match validate_positive_limit_or_default(
        request.max_lines,
        "maxLines",
        services::LOG_ENTRIES_LIMIT_DEFAULT,
        services::LOG_ENTRIES_LIMIT_DEFAULT,
    ) {
        Ok(max_lines) => max_lines,
        Err(response) => return response,
    };

    run_blocking_read(move || services::get_log_entries(max_lines)).await
}

async fn handle_get_available_models(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        MODEL_DISCOVERY_READ_BODY_MAX_BYTES,
        "get_available_models",
    ) {
        return response;
    }
    if let Err(response) = parse_empty_json_object_body::<EmptyModelDiscoveryRequest>(body) {
        return response;
    }

    success_response(services::get_available_models().await)
}

async fn handle_get_available_pi_models(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        MODEL_DISCOVERY_READ_BODY_MAX_BYTES,
        "get_available_pi_models",
    ) {
        return response;
    }
    if let Err(response) = parse_empty_json_object_body::<EmptyModelDiscoveryRequest>(body) {
        return response;
    }

    success_response(services::get_available_pi_models().await)
}

async fn handle_test_embedding_endpoint(_state: WebServerState, body: &[u8]) -> Response {
    if let Err(response) = validate_body_size(
        body,
        EMBEDDING_PROBE_BODY_MAX_BYTES,
        "test_embedding_endpoint",
    ) {
        return response;
    }
    let request = match parse_required_json_object_body::<TestEmbeddingEndpointRequest>(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    let endpoint = match validate_required_probe_field(
        &request.endpoint,
        "endpoint",
        EMBEDDING_ENDPOINT_MAX_BYTES,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let model =
        match validate_required_probe_field(&request.model, "model", EMBEDDING_MODEL_MAX_BYTES) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let api_key = match validate_optional_probe_field(
        request.api_key,
        "apiKey",
        EMBEDDING_API_KEY_MAX_BYTES,
        true,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let input_type = match validate_optional_probe_field(
        request.input_type,
        "inputType",
        EMBEDDING_OPTIONAL_FIELD_MAX_BYTES,
        false,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let truncate = match validate_optional_probe_field(
        request.truncate,
        "truncate",
        EMBEDDING_OPTIONAL_FIELD_MAX_BYTES,
        false,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };

    let outcome =
        services::test_embedding_endpoint_browser(endpoint, model, api_key, input_type, truncate)
            .await;

    match &outcome {
        crate::embedding_probe::EmbeddingProbeOutcome::InvalidScheme { endpoint } => {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid endpoint: {endpoint}"),
            )
        }
        crate::embedding_probe::EmbeddingProbeOutcome::InvalidConfigField { field, message } => {
            error_response(StatusCode::BAD_REQUEST, format!("{field} {message}"))
        }
        crate::embedding_probe::EmbeddingProbeOutcome::NetworkError { message }
            if message.starts_with("Outbound probe blocked:") =>
        {
            error_response(StatusCode::BAD_REQUEST, message.clone())
        }
        _ => success_response(outcome),
    }
}

#[cfg(test)]
static TEST_WRITE_HANDLER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static TEST_WRITE_HANDLER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
async fn handle_test_read_probe() -> Response {
    success_response(serde_json::json!({ "probe": "read" }))
}

#[cfg(test)]
async fn handle_test_sensitive_read_probe() -> Response {
    success_response(serde_json::json!({ "probe": "sensitive-read" }))
}

#[cfg(test)]
async fn handle_test_write_command() -> Response {
    TEST_WRITE_HANDLER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    success_response(serde_json::json!({ "probe": "write" }))
}

fn clamp_get_memories_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(100).clamp(0, GET_MEMORIES_LIMIT_MAX)
}

fn clamp_session_filter_limit(filter: Option<db::SessionFilter>) -> Option<db::SessionFilter> {
    filter.map(|mut filter| {
        filter.limit = Some(
            filter
                .limit
                .unwrap_or(LIST_SESSIONS_LIMIT_MAX)
                .min(LIST_SESSIONS_LIMIT_MAX),
        );
        filter
    })
}

fn clamp_positive_limit(limit: Option<i64>, default: usize, max: usize) -> usize {
    match limit {
        Some(value) if value <= 0 => 1,
        Some(value) => std::cmp::min(value as usize, max),
        None => std::cmp::min(default, max),
    }
}

fn validate_body_size(body: &[u8], max_bytes: usize, command: &str) -> Result<(), Response> {
    if body.len() <= max_bytes {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{command} body exceeds max size of {max_bytes} bytes"),
        ))
    }
}

fn validate_session_id(session_id: String) -> Result<String, Response> {
    let trimmed = session_id.trim();
    if trimmed.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "sessionId must be non-empty",
        ));
    }
    if trimmed.len() > 512 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "sessionId exceeds max length of 512",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_positive_limit_or_default(
    value: Option<i64>,
    field_name: &str,
    default: usize,
    max: usize,
) -> Result<usize, Response> {
    match value {
        None => Ok(default),
        Some(value) => validate_positive_limit_value(value, field_name, max),
    }
}

fn validate_positive_limit_value(
    value: i64,
    field_name: &str,
    max: usize,
) -> Result<usize, Response> {
    if value <= 0 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} must be positive"),
        ));
    }
    if value > max as i64 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} exceeds max value of {max}"),
        ));
    }
    Ok(value as usize)
}

fn validate_optional_non_negative_i64(
    value: Option<i64>,
    field_name: &str,
) -> Result<Option<i64>, Response> {
    match value {
        Some(value) if value < 0 => Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} must be >= 0"),
        )),
        _ => Ok(value),
    }
}

fn validate_positive_id(id: i64, field_name: &str) -> Result<(), Response> {
    if id > 0 {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} must be positive"),
        ))
    }
}

fn validate_content_size(content: &str) -> Result<(), Response> {
    if content.len() <= services::SESSION_VIEWER_CONTENT_MAX_BYTES {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "content exceeds max size of {} bytes",
                services::SESSION_VIEWER_CONTENT_MAX_BYTES
            ),
        ))
    }
}

fn validate_user_memory_status(status: Option<String>) -> Result<Option<String>, Response> {
    match status {
        None => Ok(None),
        Some(status) if status == "active" || status == "dismissed" => Ok(Some(status)),
        Some(status) => Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("status must be one of: active, dismissed (got {status})"),
        )),
    }
}

fn validate_user_memory_content(content: &str) -> Result<(), Response> {
    if content.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "content must be non-empty",
        ));
    }
    if content.len() > USER_MEMORY_CONTENT_MAX_BYTES {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "content exceeds max size of {} bytes",
                USER_MEMORY_CONTENT_MAX_BYTES
            ),
        ));
    }
    Ok(())
}

fn validate_config_content(content: &str) -> Result<(), Response> {
    if content.len() > CONFIG_CONTENT_MAX_BYTES {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "content exceeds max size of {} bytes",
                CONFIG_CONTENT_MAX_BYTES
            ),
        ));
    }
    Ok(())
}

fn validate_project_path(project_path: &str) -> Result<String, Response> {
    let trimmed = project_path.trim();
    if trimmed.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "projectPath must be non-empty",
        ));
    }
    if trimmed.len() > PROJECT_PATH_MAX_BYTES {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "projectPath exceeds max size of {} bytes",
                PROJECT_PATH_MAX_BYTES
            ),
        ));
    }
    if !FsPath::new(trimmed).is_absolute() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "projectPath must be absolute",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_project_path_option(project_path: Option<String>) -> Result<Option<String>, Response> {
    match project_path {
        Some(project_path) => validate_project_path(&project_path).map(Some),
        None => Ok(None),
    }
}

fn parse_user_memory_id_request(
    body: &[u8],
    command: &str,
) -> Result<UserMemoryIdRequest, Response> {
    validate_body_size(body, USER_MEMORY_ID_BODY_MAX_BYTES, command)?;
    let request = parse_required_json_body::<UserMemoryIdRequest>(body)?;
    validate_positive_id(request.id, "id")?;
    Ok(request)
}

async fn run_blocking_read<T, F>(work: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(data)) => success_response(data),
        Ok(Err(error)) => error_response(StatusCode::BAD_REQUEST, error),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("blocking task failed: {error}"),
        ),
    }
}

async fn run_blocking_write<T, F>(work: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(data)) => success_response(data),
        Ok(Err(error)) => error_response(StatusCode::BAD_REQUEST, error),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("blocking task failed: {error}"),
        ),
    }
}

fn parse_json_body<T>(body: &[u8]) -> Result<T, Response>
where
    T: DeserializeOwned + Default,
{
    if body.is_empty() {
        return Ok(T::default());
    }

    serde_json::from_slice(body).map_err(|error| {
        error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid JSON body: {error}"),
        )
    })
}

fn parse_required_json_body<T>(body: &[u8]) -> Result<T, Response>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(body).map_err(|error| {
        error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid JSON body: {error}"),
        )
    })
}

fn parse_required_json_object_body<T>(body: &[u8]) -> Result<T, Response>
where
    T: DeserializeOwned,
{
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid JSON body: {error}"),
        )
    })?;

    match value {
        serde_json::Value::Object(_) => serde_json::from_value(value).map_err(|error| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON body: {error}"),
            )
        }),
        _ => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid JSON body: expected object",
        )),
    }
}

fn parse_empty_json_object_body<T>(body: &[u8]) -> Result<T, Response>
where
    T: DeserializeOwned + Default,
{
    if body.is_empty() {
        return Ok(T::default());
    }

    let value: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid JSON body: {error}"),
        )
    })?;

    match value {
        serde_json::Value::Object(ref map) if map.is_empty() => serde_json::from_value(value)
            .map_err(|error| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid JSON body: {error}"),
                )
            }),
        serde_json::Value::Object(_) => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid JSON body: expected empty object",
        )),
        _ => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid JSON body: expected empty object",
        )),
    }
}

fn success_response<T: Serialize>(data: T) -> Response {
    (StatusCode::OK, Json(SuccessEnvelope { ok: true, data })).into_response()
}

fn validate_api_request(headers: &HeaderMap, server_port: u16) -> Result<(), Response> {
    validate_host(headers)?;
    validate_origin(headers, server_port)?;
    validate_content_type(headers)?;
    Ok(())
}

fn validate_host(headers: &HeaderMap) -> Result<(), Response> {
    let host = header_value(headers, header::HOST)
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "missing Host header"))?;
    let (host_name, _) = parse_host_port(&host)
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "invalid Host header"))?;

    if is_local_host(host_name) {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::FORBIDDEN,
            format!("non-local Host rejected: {host}"),
        ))
    }
}

fn validate_origin(headers: &HeaderMap, server_port: u16) -> Result<(), Response> {
    let Some(origin) = header_value(headers, header::ORIGIN) else {
        return Ok(());
    };

    let uri: axum::http::Uri = origin
        .parse()
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "invalid Origin header"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "invalid Origin header"))?;
    if scheme != "http" && scheme != "https" {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            format!("Origin scheme not allowed: {origin}"),
        ));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "invalid Origin header"))?;
    let host = authority.host();
    let port = authority.port_u16();
    let allowed_port = matches!(port, Some(p) if p == VITE_DEV_PORT || p == server_port);

    if is_local_host(host) && allowed_port {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::FORBIDDEN,
            format!("Origin not allowed: {origin}"),
        ))
    }
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), Response> {
    let content_type = header_value(headers, header::CONTENT_TYPE).ok_or_else(|| {
        error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        )
    })?;

    if content_type
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        ))
    }
}

fn header_value(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn parse_host_port(input: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = input.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(value) => Some(value.parse::<u16>().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((host, port));
    }

    if let Some((host, port)) = input.rsplit_once(':') {
        if host.contains(':') {
            return Some((input, None));
        }
        return Some((host, Some(port.parse::<u16>().ok()?)));
    }

    Some((input, None))
}

fn is_local_host(host: &str) -> bool {
    LOCAL_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn error_response(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorEnvelope {
            ok: false,
            error: error.into(),
        }),
    )
        .into_response()
}

fn validate_required_probe_field(
    value: &str,
    field_name: &str,
    max_bytes: usize,
) -> Result<String, Response> {
    if value.chars().any(char::is_control) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} contains control characters"),
        ));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} is required"),
        ));
    }
    if trimmed.len() > max_bytes {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} exceeds {max_bytes} bytes"),
        ));
    }
    if let Some(token) = find_file_token(trimmed) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "{field_name} contains unsupported token {}",
                redact_file_token_for_error(&token)
            ),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_optional_probe_field(
    value: Option<String>,
    field_name: &str,
    max_bytes: usize,
    enforce_raw_limit: bool,
) -> Result<Option<String>, Response> {
    let Some(value) = value else {
        return Ok(None);
    };
    if enforce_raw_limit && value.len() > max_bytes {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} exceeds {max_bytes} bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} contains control characters"),
        ));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > max_bytes {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("{field_name} exceeds {max_bytes} bytes"),
        ));
    }
    if let Some(token) = find_file_token(trimmed) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "{field_name} contains unsupported token {}",
                redact_file_token_for_error(&token)
            ),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn redact_file_token_for_error(token: &str) -> &str {
    if token.starts_with("{file:") {
        "{file:...}"
    } else {
        token
    }
}

fn find_file_token(input: &str) -> Option<String> {
    let start = input.find("{file:")?;
    let rest = &input[start..];
    let end = rest.find('}')?;
    Some(rest[..=end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use serde_json::Value;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use tempfile::tempdir;
    use tower::util::ServiceExt;

    const TEST_LOCAL_AUTH_TOKEN: &str = "test-local-auth-token";
    static PI_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static CONFIG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static LOG_ROUTE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static MODEL_DISCOVERY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn get_db_health_returns_success_envelope_with_token() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute("CREATE TABLE memories (id INTEGER PRIMARY KEY)", [])
            .expect("create memories");
        conn.execute("CREATE TABLE compartments (id INTEGER PRIMARY KEY)", [])
            .expect("create compartments");
        conn.execute("CREATE TABLE session_facts (id INTEGER PRIMARY KEY)", [])
            .expect("create session_facts");
        conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY)", [])
            .expect("create notes");
        conn.execute("CREATE TABLE session_meta (id INTEGER PRIMARY KEY)", [])
            .expect("create session_meta");
        conn.execute("CREATE TABLE tags (id INTEGER PRIMARY KEY)", [])
            .expect("create tags");
        conn.execute("CREATE TABLE pending_ops (id INTEGER PRIMARY KEY)", [])
            .expect("create pending_ops");
        conn.execute("CREATE TABLE dream_queue (id INTEGER PRIMARY KEY)", [])
            .expect("create dream_queue");
        conn.execute("CREATE TABLE dream_state (id INTEGER PRIMARY KEY)", [])
            .expect("create dream_state");

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_request_with_token(
                "/api/get_db_health",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["ok"], Value::Bool(true));
        assert_eq!(json["data"]["exists"], Value::Bool(true));
    }

    #[tokio::test]
    async fn get_dashboard_schema_warning_returns_success_envelope() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request("/api/get_dashboard_schema_warning"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["ok"], Value::Bool(true));
        assert!(json["data"].is_null() || json["data"].is_number());
    }

    #[tokio::test]
    async fn sensitive_read_rejects_without_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request("/api/test_sensitive_read_probe"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sensitive_read_allows_valid_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request_with_token(
                "/api/test_sensitive_read_probe",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_non_local_host() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/get_db_health")
                    .header(header::HOST, "evil.example")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_invalid_origin_port() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/get_db_health")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::ORIGIN, "http://127.0.0.1:3000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_non_http_origin_scheme() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/get_db_health")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::ORIGIN, "file://127.0.0.1:1420")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_non_json_content_type() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/get_db_health")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn unknown_command_returns_structured_404() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request("/api/nope"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["ok"], Value::Bool(false));
    }

    #[tokio::test]
    async fn api_unknown_path_does_not_fall_back_to_static() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("index.html"),
            "<html><body>dashboard</body></html>",
        )
        .expect("write index");
        let app = build_router(test_state_with_dist(
            None,
            1422,
            Some(temp_dir.path().to_path_buf()),
        ));
        let response = app
            .oneshot(valid_get_request("/api/unknown"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["ok"], Value::Bool(false));
    }

    #[tokio::test]
    async fn serves_static_index_for_root() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("index.html"),
            "<html><body>dashboard root</body></html>",
        )
        .expect("write index");

        let app = build_router(test_state_with_dist(
            None,
            1422,
            Some(temp_dir.path().to_path_buf()),
        ));
        let response = app.oneshot(valid_get_request("/")).await.expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("dashboard root"));
        assert!(text.contains("magic-context-bootstrap"));
        assert!(text.contains(TEST_LOCAL_AUTH_TOKEN));
    }

    #[tokio::test]
    async fn serves_spa_fallback_for_unknown_non_api_path() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("index.html"),
            "<html><body>spa shell</body></html>",
        )
        .expect("write index");

        let app = build_router(test_state_with_dist(
            None,
            1422,
            Some(temp_dir.path().to_path_buf()),
        ));
        let response = app
            .oneshot(valid_get_request("/sessions/abc"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("spa shell"));
        assert!(text.contains("magic-context-bootstrap"));
    }

    #[tokio::test]
    async fn static_assets_do_not_include_bootstrap_token() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("index.html"),
            "<html><head></head><body>shell</body></html>",
        )
        .expect("write index");
        fs::write(temp_dir.path().join("app.js"), "console.log('asset');").expect("write asset");

        let app = build_router(test_state_with_dist(
            None,
            1422,
            Some(temp_dir.path().to_path_buf()),
        ));
        let response = app
            .oneshot(valid_get_request("/app.js"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CACHE_CONTROL).is_none());
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(!text.contains("magic-context-bootstrap"));
        assert!(!text.contains(TEST_LOCAL_AUTH_TOKEN));
    }

    #[tokio::test]
    async fn missing_dist_returns_build_hint() {
        let app = build_router(test_state_with_dist(None, 1422, None));
        let response = app.oneshot(valid_get_request("/")).await.expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("bun run build"));
    }

    #[tokio::test]
    async fn write_command_rejects_without_token() {
        let _guard = TEST_WRITE_HANDLER_LOCK.lock().expect("write test lock");
        TEST_WRITE_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request("/api/test_write_command"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(TEST_WRITE_HANDLER_CALLS.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn write_command_with_valid_token_reaches_handler() {
        let _guard = TEST_WRITE_HANDLER_LOCK.lock().expect("write test lock");
        TEST_WRITE_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request_with_token(
                "/api/test_write_command",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(TEST_WRITE_HANDLER_CALLS.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn read_command_does_not_require_local_control_header() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request("/api/test_read_probe"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn memory_write_endpoint_rejects_without_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/update_memory_status",
                serde_json::json!({ "memoryId": 1, "status": "archived" }),
                None,
                true,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn side_effect_endpoint_rejects_without_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/delete_memory",
                serde_json::json!({ "memoryId": 1 }),
                None,
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn memory_write_endpoint_rejects_invalid_json_body() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/update_memory_status",
                serde_json::json!({ "status": "archived" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                true,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["ok"], Value::Bool(false));
    }

    #[tokio::test]
    async fn update_memory_status_success_path_returns_success_envelope() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute_batch(
            "CREATE TABLE memories (
                id INTEGER PRIMARY KEY,
                project_path TEXT NOT NULL,
                category TEXT,
                content TEXT NOT NULL,
                normalized_hash TEXT,
                status TEXT,
                updated_at INTEGER
            );
            CREATE TABLE project_state (
                project_path TEXT PRIMARY KEY,
                project_memory_epoch INTEGER NOT NULL,
                project_user_profile_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE memory_mutation_log (
                id INTEGER PRIMARY KEY,
                project_path TEXT NOT NULL,
                mutation_type TEXT NOT NULL,
                target_memory_id INTEGER NOT NULL,
                superseded_by_id INTEGER,
                category TEXT,
                new_content TEXT,
                queued_at INTEGER NOT NULL
            );",
        )
        .expect("create memory mutation schema");
        conn.execute(
            "INSERT INTO memories (id, project_path, category, content, normalized_hash, status, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                1_i64,
                "/tmp/project",
                "fact",
                "memory content",
                "hash",
                "active",
                0_i64
            ],
        )
        .expect("insert memory");

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/update_memory_status",
                serde_json::json!({ "memoryId": 1, "status": "archived" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                true,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["ok"], Value::Bool(true));
        assert_eq!(json["data"], Value::Null);

        let conn = rusqlite::Connection::open(&db_path).expect("reopen db");
        let status: String = conn
            .query_row("SELECT status FROM memories WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("query status");
        assert_eq!(status, "archived");
    }

    #[tokio::test]
    async fn missing_origin_allows_basic_read_without_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request_without_origin(
                "/api/get_dashboard_schema_warning",
                None,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_origin_rejects_protected_without_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request_without_origin(
                "/api/test_sensitive_read_probe",
                None,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn missing_origin_allows_protected_with_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_request_without_origin(
                "/api/test_sensitive_read_probe",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn old_static_local_header_alone_rejected_for_protected_command() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/update_memory_status",
                serde_json::json!({ "memoryId": 1, "status": "archived" }),
                None,
                true,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn wrong_or_empty_token_rejected_for_protected_command() {
        let app = build_router(test_state(None, 1422));

        let wrong_token_response = app
            .clone()
            .oneshot(valid_request_with_token(
                "/api/test_sensitive_read_probe",
                Some("wrong-token"),
            ))
            .await
            .expect("response");
        assert_eq!(wrong_token_response.status(), StatusCode::FORBIDDEN);

        let empty_token_response = app
            .oneshot(valid_request_with_token(
                "/api/test_sensitive_read_probe",
                Some(""),
            ))
            .await
            .expect("response");
        assert_eq!(empty_token_response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn session_cache_phase_one_routes_are_sensitive_read_and_deferred_routes_absent() {
        for command in [
            "get_session_messages",
            "get_session_cache_events",
            "get_session_cache_events_by_turns",
            "get_cache_events_from_db",
        ] {
            let spec = find_command_spec(command).expect("route present");
            assert_eq!(spec.access, CommandAccess::SensitiveRead, "{command}");
        }

        for command in [
            "enqueue_dream",
            "delete_dream_queue_entry",
            "get_session_cache_stats",
            "get_session_cache_stats_from_db",
            "get_context_token_breakdown",
            "list_processes",
            "invoke_backend_command",
            "get_session_facts",
            "get_session_notes",
        ] {
            assert!(
                find_command_spec(command).is_none(),
                "{command} should stay absent"
            );
        }
    }

    #[test]
    fn user_memory_phase_two_routes_have_exact_access_and_deferred_routes_absent() {
        let expected = [
            ("get_user_memories", CommandAccess::SensitiveRead),
            ("get_user_memory_candidates", CommandAccess::SensitiveRead),
            ("dismiss_user_memory", CommandAccess::Write),
            ("delete_user_memory", CommandAccess::SideEffect),
            ("update_user_memory_content", CommandAccess::Write),
            ("delete_user_memory_candidate", CommandAccess::SideEffect),
            ("promote_user_memory_candidate", CommandAccess::SideEffect),
        ];

        for (command, access) in expected {
            let spec = find_command_spec(command).expect("route present");
            assert_eq!(spec.access, access, "{command}");
        }

        for command in [
            "update_user_memory_candidate",
            "bulk_delete_user_memories",
            "bulk_dismiss_user_memories",
            "invoke_backend_command",
            "enqueue_dream",
            "delete_dream_queue_entry",
            "list_processes",
        ] {
            assert!(
                find_command_spec(command).is_none(),
                "{command} should stay absent"
            );
        }
    }

    #[test]
    fn model_discovery_phase_four_b_routes_have_exact_access_and_forbidden_routes_stay_absent() {
        for command in ["get_available_models", "get_available_pi_models"] {
            let spec = find_command_spec(command).expect("route present");
            assert_eq!(spec.access, CommandAccess::Process, "{command}");
        }

        for command in [
            "list_processes",
            "invoke_backend_command",
            "enqueue_dream",
            "delete_dream_queue_entry",
            "get_session_cache_stats",
            "get_session_cache_stats_from_db",
            "get_context_token_breakdown",
            "enumerate_projects",
            "enumerate_memory_projects",
            "get_session_facts",
            "get_session_notes",
        ] {
            assert!(
                find_command_spec(command).is_none(),
                "{command} should stay absent"
            );
        }
    }

    #[tokio::test]
    async fn model_discovery_routes_require_valid_token() {
        let _guard = MODEL_DISCOVERY_TEST_LOCK
            .lock()
            .expect("model discovery test lock");
        crate::model_discovery::set_test_candidates(
            "opencode",
            Some(vec![missing_candidate_path("opencode")]),
        );
        crate::model_discovery::set_test_candidates("pi", Some(vec![missing_candidate_path("pi")]));

        let app = build_router(test_state(None, 1422));
        for uri in ["/api/get_available_models", "/api/get_available_pi_models"] {
            let forbidden = app
                .clone()
                .oneshot(valid_empty_body_request(uri, None))
                .await
                .expect("response without token");
            assert_eq!(forbidden.status(), StatusCode::FORBIDDEN, "{uri}");

            let wrong = app
                .clone()
                .oneshot(valid_empty_body_request(uri, Some("wrong-token")))
                .await
                .expect("response with wrong token");
            assert_eq!(wrong.status(), StatusCode::FORBIDDEN, "{uri}");

            let allowed = app
                .clone()
                .oneshot(valid_empty_body_request(uri, Some(TEST_LOCAL_AUTH_TOKEN)))
                .await
                .expect("response with token");
            assert_eq!(allowed.status(), StatusCode::OK, "{uri}");
        }

        crate::model_discovery::set_test_candidates("opencode", None);
        crate::model_discovery::set_test_candidates("pi", None);
    }

    #[tokio::test]
    async fn model_discovery_routes_validate_empty_object_only_and_body_size() {
        let _guard = MODEL_DISCOVERY_TEST_LOCK
            .lock()
            .expect("model discovery test lock");
        crate::model_discovery::set_test_candidates(
            "opencode",
            Some(vec![missing_candidate_path("opencode")]),
        );
        crate::model_discovery::set_test_candidates("pi", Some(vec![missing_candidate_path("pi")]));

        let app = build_router(test_state(None, 1422));

        for uri in ["/api/get_available_models", "/api/get_available_pi_models"] {
            let empty = app
                .clone()
                .oneshot(valid_empty_body_request(uri, Some(TEST_LOCAL_AUTH_TOKEN)))
                .await
                .expect("empty body response");
            assert_eq!(empty.status(), StatusCode::OK, "{uri}");

            let object = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    serde_json::json!({}),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("object body response");
            assert_eq!(object.status(), StatusCode::OK, "{uri}");

            for body in ["null", "[]", "\"models\"", "{", r#"{"extra":true}"#] {
                let response = app
                    .clone()
                    .oneshot(valid_raw_json_request(
                        uri,
                        body,
                        Some(TEST_LOCAL_AUTH_TOKEN),
                    ))
                    .await
                    .expect("bad body response");
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "{uri} body={body}"
                );
            }

            let oversized = app
                .clone()
                .oneshot(valid_raw_json_request(
                    uri,
                    &format!(
                        "{{\"padding\":\"{}\"}}",
                        "x".repeat(MODEL_DISCOVERY_READ_BODY_MAX_BYTES)
                    ),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                ))
                .await
                .expect("oversized response");
            assert_eq!(oversized.status(), StatusCode::BAD_REQUEST, "{uri}");
        }

        crate::model_discovery::set_test_candidates("opencode", None);
        crate::model_discovery::set_test_candidates("pi", None);
    }

    #[tokio::test]
    async fn model_discovery_routes_parse_sanitize_and_fix_argv() {
        let _guard = MODEL_DISCOVERY_TEST_LOCK
            .lock()
            .expect("model discovery test lock");
        let temp_dir = tempdir().expect("temp dir");
        let opencode_argv = temp_dir.path().join("opencode.argv");
        let pi_argv = temp_dir.path().join("pi.argv");

        let overlong = "x".repeat(257);
        let opencode_stdout = format!(" alpha \nalpha\nbe\u{0007}ta\n{overlong}\n");
        let opencode_stdout_json = serde_json::to_string(&opencode_stdout).expect("stdout json");
        let opencode_script = create_python_executable(
            temp_dir.path().join("fake-opencode.py"),
            &format!(
                "import pathlib, sys\npathlib.Path(r\"{}\").write_text('\\n'.join(sys.argv[1:]), encoding='utf-8')\nsys.stdout.buffer.write({opencode_stdout_json}.encode('utf-8'))\n",
                opencode_argv.display(),
            ),
        );
        let pi_script = create_python_executable(
            temp_dir.path().join("fake-pi.py"),
            &format!(
                "import pathlib, sys\npathlib.Path(r\"{}\").write_text('\\n'.join(sys.argv[1:]), encoding='utf-8')\nsys.stdout.write('PROVIDER MODEL STATUS\\nopenai gpt-4o ready\\nopenai gpt-4o dup\\nanthropic claude-sonnet online\\n')\n",
                pi_argv.display(),
            ),
        );

        crate::model_discovery::set_test_candidates(
            "opencode",
            Some(vec![opencode_script.to_string_lossy().into_owned()]),
        );
        crate::model_discovery::set_test_candidates(
            "pi",
            Some(vec![pi_script.to_string_lossy().into_owned()]),
        );

        let app = build_router(test_state(None, 1422));
        let opencode_json = read_ok_json(
            app.clone()
                .oneshot(valid_empty_body_request(
                    "/api/get_available_models",
                    Some(TEST_LOCAL_AUTH_TOKEN),
                ))
                .await
                .expect("opencode response"),
        )
        .await;
        assert_eq!(opencode_json["data"], serde_json::json!(["alpha", "beta"]),);
        assert_eq!(
            fs::read_to_string(&opencode_argv)
                .expect("read opencode argv")
                .trim(),
            "models"
        );

        let pi_json = read_ok_json(
            app.oneshot(valid_json_request(
                "/api/get_available_pi_models",
                serde_json::json!({}),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("pi response"),
        )
        .await;
        assert_eq!(
            pi_json["data"],
            serde_json::json!(["anthropic/claude-sonnet", "openai/gpt-4o"]),
        );
        assert_eq!(
            fs::read_to_string(&pi_argv).expect("read pi argv").trim(),
            "--list-models"
        );

        crate::model_discovery::set_test_candidates("opencode", None);
        crate::model_discovery::set_test_candidates("pi", None);
    }

    #[tokio::test]
    async fn model_discovery_routes_cap_output_timeout_and_hide_stderr() {
        let _guard = MODEL_DISCOVERY_TEST_LOCK
            .lock()
            .expect("model discovery test lock");
        let temp_dir = tempdir().expect("temp dir");

        let huge_script = create_python_executable(
            temp_dir.path().join("huge-opencode.py"),
            "import sys\nsys.stdout.write('m' * (131072 + 2048))\n",
        );
        crate::model_discovery::set_test_candidates(
            "opencode",
            Some(vec![huge_script.to_string_lossy().into_owned()]),
        );

        let app = build_router(test_state(None, 1422));
        let huge_json = read_ok_json(
            app.clone()
                .oneshot(valid_empty_body_request(
                    "/api/get_available_models",
                    Some(TEST_LOCAL_AUTH_TOKEN),
                ))
                .await
                .expect("huge stdout response"),
        )
        .await;
        assert_eq!(huge_json["data"], serde_json::json!([]));

        let pid_file = temp_dir.path().join("hang.pid");
        let hang_script = create_python_executable(
            temp_dir.path().join("hang-pi.py"),
            &format!(
                "import os, pathlib, time\npathlib.Path(r\"{}\").write_text(str(os.getpid()), encoding='utf-8')\ntime.sleep(30)\n",
                pid_file.display(),
            ),
        );
        crate::model_discovery::set_test_candidates(
            "pi",
            Some(vec![hang_script.to_string_lossy().into_owned()]),
        );

        let started = std::time::Instant::now();
        let timeout_json = read_ok_json(
            app.clone()
                .oneshot(valid_empty_body_request(
                    "/api/get_available_pi_models",
                    Some(TEST_LOCAL_AUTH_TOKEN),
                ))
                .await
                .expect("timeout response"),
        )
        .await;
        assert!(started.elapsed() < std::time::Duration::from_secs(8));
        assert_eq!(timeout_json["data"], serde_json::json!([]));

        let pid = fs::read_to_string(&pid_file)
            .expect("pid file")
            .trim()
            .parse::<u32>()
            .expect("pid");
        wait_for_pid_exit(pid);

        let secret = "sk-test-super-secret-value";
        let nonzero_script = create_python_executable(
            temp_dir.path().join("nonzero-opencode.py"),
            &format!("import sys\nsys.stderr.write({secret:?})\nsys.exit(7)\n",),
        );
        crate::model_discovery::set_test_candidates(
            "opencode",
            Some(vec![nonzero_script.to_string_lossy().into_owned()]),
        );

        let nonzero_response = app
            .oneshot(valid_empty_body_request(
                "/api/get_available_models",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("nonzero response");
        let nonzero_body = to_bytes(nonzero_response.into_body(), usize::MAX)
            .await
            .expect("nonzero body");
        let nonzero_text = String::from_utf8(nonzero_body.to_vec()).expect("nonzero utf8");
        assert!(!nonzero_text.contains(secret));

        crate::model_discovery::set_test_candidates("opencode", None);
        crate::model_discovery::set_test_candidates("pi", None);
    }

    #[tokio::test]
    async fn model_discovery_routes_cap_model_count_at_one_thousand() {
        let _guard = MODEL_DISCOVERY_TEST_LOCK
            .lock()
            .expect("model discovery test lock");
        let temp_dir = tempdir().expect("temp dir");
        let script = create_python_executable(
            temp_dir.path().join("many-models.py"),
            "for idx in range(1200):\n    print(f'model-{idx}')\n",
        );
        crate::model_discovery::set_test_candidates(
            "opencode",
            Some(vec![script.to_string_lossy().into_owned()]),
        );

        let app = build_router(test_state(None, 1422));
        let json = read_ok_json(
            app.oneshot(valid_empty_body_request(
                "/api/get_available_models",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("many models response"),
        )
        .await;

        let models = json["data"].as_array().expect("array");
        assert_eq!(models.len(), 1000);
        assert_eq!(models.first().and_then(Value::as_str), Some("model-0"));
        assert_eq!(models.last().and_then(Value::as_str), Some("model-999"));

        crate::model_discovery::set_test_candidates("opencode", None);
    }

    #[test]
    fn embedding_probe_phase_four_c_route_has_exact_access_and_only_expected_surface() {
        let spec = find_command_spec("test_embedding_endpoint").expect("route present");
        assert_eq!(spec.access, CommandAccess::OutboundProbe);

        for command in [
            "invoke_backend_command",
            "list_processes",
            "enqueue_dream",
            "delete_dream_queue_entry",
            "get_cache_events",
            "get_session_cache_stats",
            "get_session_cache_stats_from_db",
            "get_context_token_breakdown",
            "enumerate_projects",
            "enumerate_memory_projects",
            "get_session_facts",
            "get_session_notes",
        ] {
            assert!(
                find_command_spec(command).is_none(),
                "{command} should stay absent"
            );
        }
    }

    #[tokio::test]
    async fn embedding_probe_route_requires_token_and_keeps_host_origin_content_type_guards() {
        let (addr, handle) = spawn_test_server(axum::Router::new().route(
            "/v1/embeddings",
            axum::routing::post(|| async {
                Json(serde_json::json!({ "data": [{ "embedding": [0.1, 0.2] }] }))
            }),
        ))
        .await;
        let endpoint = format!("http://127.0.0.1:{}/v1", addr.port());
        let payload = serde_json::json!({ "endpoint": endpoint, "model": "test-model" });
        let app = build_router(test_state(None, 1422));

        let forbidden = app
            .clone()
            .oneshot(valid_json_request(
                "/api/test_embedding_endpoint",
                payload.clone(),
                None,
                false,
            ))
            .await
            .expect("forbidden response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let bad_host = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/test_embedding_endpoint")
                    .header(header::HOST, "example.com")
                    .header(header::ORIGIN, "http://127.0.0.1:1420")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(LOCAL_AUTH_TOKEN_HEADER, TEST_LOCAL_AUTH_TOKEN)
                    .body(Body::from(payload.to_string()))
                    .expect("bad host request"),
            )
            .await
            .expect("bad host response");
        assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);

        let bad_origin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/test_embedding_endpoint")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::ORIGIN, "http://example.com")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(LOCAL_AUTH_TOKEN_HEADER, TEST_LOCAL_AUTH_TOKEN)
                    .body(Body::from(payload.to_string()))
                    .expect("bad origin request"),
            )
            .await
            .expect("bad origin response");
        assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

        let bad_content_type = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/test_embedding_endpoint")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::ORIGIN, "http://127.0.0.1:1420")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(LOCAL_AUTH_TOKEN_HEADER, TEST_LOCAL_AUTH_TOKEN)
                    .body(Body::from(payload.to_string()))
                    .expect("bad ctype request"),
            )
            .await
            .expect("bad ctype response");
        assert_eq!(
            bad_content_type.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        handle.abort();
    }

    #[tokio::test]
    async fn embedding_probe_route_rejects_invalid_schema_and_ssrf_inputs_before_network() {
        let app = build_router(test_state(None, 1422));

        for body in ["null", "[]", "\"x\"", "123", "true", "{"] {
            let response = app
                .clone()
                .oneshot(valid_raw_json_request(
                    "/api/test_embedding_endpoint",
                    body,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                ))
                .await
                .expect("invalid body response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "body={body}");
        }

        for payload in [
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "m", "extra": true }),
            serde_json::json!({ "endpoint": "", "model": "m" }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "" }),
            serde_json::json!({ "endpoint": " ", "model": "m" }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": " ", "apiKey": null }),
            serde_json::json!({ "endpoint": format!("http://127.0.0.1:1/{}", "x".repeat(EMBEDDING_ENDPOINT_MAX_BYTES + 1)), "model": "m" }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "x".repeat(EMBEDDING_MODEL_MAX_BYTES + 1) }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "m", "apiKey": "x".repeat(EMBEDDING_API_KEY_MAX_BYTES + 1) }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "m", "inputType": "x".repeat(EMBEDDING_OPTIONAL_FIELD_MAX_BYTES + 1) }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "m", "truncate": "x".repeat(EMBEDDING_OPTIONAL_FIELD_MAX_BYTES + 1) }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1\n", "model": "m" }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "m\u{0007}" }),
            serde_json::json!({ "endpoint": "{file:/tmp/secret}", "model": "m" }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "{file:/tmp/secret}" }),
            serde_json::json!({ "endpoint": "http://127.0.0.1:1/v1", "model": "m", "apiKey": "{file:/tmp/secret}" }),
            serde_json::json!({ "endpoint": "file:///tmp/secret", "model": "m" }),
            serde_json::json!({ "endpoint": "gopher://example.com", "model": "m" }),
            serde_json::json!({ "endpoint": "http://example.com/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "http://10.0.0.1/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "http://172.16.0.1/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "http://192.168.0.1/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "http://169.254.169.254/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "http://0.0.0.0/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "http://[::]/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "http://[fd00::1]/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "https://user:pass@example.com/v1", "model": "m" }),
            serde_json::json!({ "endpoint": "https://example.com/v1?x=1", "model": "m" }),
            serde_json::json!({ "endpoint": "https://example.com/v1#frag", "model": "m" }),
        ] {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    "/api/test_embedding_endpoint",
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("invalid payload response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let oversized = app
            .oneshot(valid_raw_json_request(
                "/api/test_embedding_endpoint",
                &format!(
                    "{{\"endpoint\":\"http://127.0.0.1:1/v1\",\"model\":\"m\",\"padding\":\"{}\"}}",
                    "x".repeat(EMBEDDING_PROBE_BODY_MAX_BYTES)
                ),
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("oversized response");
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn embedding_probe_route_revalidates_env_expanded_values_without_echoing_secrets() {
        std::env::set_var(
            "MC_TEST_BROWSER_ENDPOINT_LONG",
            format!("https://example.com/{}", "x".repeat(2048)),
        );
        std::env::set_var("MC_TEST_BROWSER_MODEL_LONG", "m".repeat(513));
        std::env::set_var("MC_TEST_BROWSER_API_KEY_LONG", "k".repeat(8193));
        std::env::set_var("MC_TEST_BROWSER_API_KEY_CTRL", "abc\ndef");
        std::env::set_var("MC_TEST_BROWSER_FILE_TOKEN", "{file:/super/secret/path}");

        let app = build_router(test_state(None, 1422));
        let cases = [
            (
                serde_json::json!({
                    "endpoint": "{env:MC_TEST_BROWSER_ENDPOINT_LONG}",
                    "model": "ok"
                }),
                "endpoint exceeds max length of 2048 bytes",
                None,
            ),
            (
                serde_json::json!({
                    "endpoint": "https://example.com/v1",
                    "model": "{env:MC_TEST_BROWSER_MODEL_LONG}"
                }),
                "model exceeds max length of 512 bytes",
                None,
            ),
            (
                serde_json::json!({
                    "endpoint": "https://example.com/v1",
                    "model": "ok",
                    "apiKey": "{env:MC_TEST_BROWSER_API_KEY_LONG}"
                }),
                "apiKey exceeds max length of 8192 bytes",
                Some("k".repeat(32)),
            ),
            (
                serde_json::json!({
                    "endpoint": "https://example.com/v1",
                    "model": "ok",
                    "apiKey": "{env:MC_TEST_BROWSER_API_KEY_CTRL}"
                }),
                "apiKey contains control characters",
                Some("abc\ndef".to_string()),
            ),
            (
                serde_json::json!({
                    "endpoint": "https://example.com/v1",
                    "model": "ok",
                    "apiKey": "{env:MC_TEST_BROWSER_FILE_TOKEN}"
                }),
                "apiKey contains unsupported {file:...} token",
                Some("/super/secret/path".to_string()),
            ),
        ];

        for (payload, expected_error, forbidden_snippet) in cases {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    "/api/test_embedding_endpoint",
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("env validation response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("env validation body");
            let text = String::from_utf8(body.to_vec()).expect("env validation utf8");
            assert!(text.contains(expected_error), "body={text}");
            if let Some(snippet) = forbidden_snippet.as_deref() {
                assert!(
                    !text.contains(snippet),
                    "body leaked secret snippet: {text}"
                );
            }
        }

        for key in [
            "MC_TEST_BROWSER_ENDPOINT_LONG",
            "MC_TEST_BROWSER_MODEL_LONG",
            "MC_TEST_BROWSER_API_KEY_LONG",
            "MC_TEST_BROWSER_API_KEY_CTRL",
            "MC_TEST_BROWSER_FILE_TOKEN",
        ] {
            std::env::remove_var(key);
        }
    }

    #[tokio::test]
    async fn embedding_probe_route_supports_loopback_success_redirect_and_redaction() {
        let second_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let second_hits_clone = second_hits.clone();
        let (second_addr, second_handle) = spawn_test_server(axum::Router::new().route(
            "/private/embeddings",
            axum::routing::post(move || {
                let second_hits = second_hits_clone.clone();
                async move {
                    second_hits.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({ "data": [{ "embedding": [9.9] }] }))
                }
            }),
        ))
        .await;

        let redirect_target = format!("http://127.0.0.1:{}/private/embeddings", second_addr.port());
        let secret = "sk-test-super-secret-value";
        let (first_addr, first_handle) = spawn_test_server(
            axum::Router::new()
                .route(
                    "/v1/embeddings",
                    axum::routing::post({
                        let redirect_target = redirect_target.clone();
                        move |headers: HeaderMap, body: Bytes| {
                            let redirect_target = redirect_target.clone();
                            async move {
                                let auth = headers
                                    .get(header::AUTHORIZATION)
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or_default()
                                    .to_string();
                                let body_text = String::from_utf8_lossy(&body).into_owned();
                                if body_text.contains("redirect-me") {
                                    return Response::builder()
                                        .status(StatusCode::FOUND)
                                        .header(header::LOCATION, redirect_target)
                                        .body(Body::empty())
                                        .expect("redirect response");
                                }
                                if body_text.contains("too-large") {
                                    return Response::builder()
                                        .status(StatusCode::OK)
                                        .header(
                                            header::CONTENT_LENGTH,
                                            (512 * 1024 + 1).to_string(),
                                        )
                                        .body(Body::from(vec![b'x'; 512 * 1024 + 1]))
                                        .expect("too large response");
                                }
                                if body_text.contains("leak-me") {
                                    return Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .header(header::CONTENT_TYPE, "text/plain")
                                        .body(Body::from(format!(
                                            "secret={secret}; auth={auth}; body={body_text}"
                                        )))
                                        .expect("leak response");
                                }
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .body(Body::from(
                                        serde_json::json!({
                                            "data": [{ "embedding": [0.1, 0.2, 0.3] }]
                                        })
                                        .to_string(),
                                    ))
                                    .expect("ok response")
                            }
                        }
                    }),
                )
                .route(
                    "/large/embeddings",
                    axum::routing::post(|| async move {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(vec![b'x'; 512 * 1024 + 1]))
                            .expect("large body response")
                    }),
                ),
        )
        .await;

        let app = build_router(test_state(None, 1422));
        let base_endpoint = format!("http://127.0.0.1:{}/v1", first_addr.port());
        let localhost_endpoint = format!("http://localhost:{}/v1", first_addr.port());

        let success_json = read_ok_json(
            app.clone()
                .oneshot(valid_json_request(
                    "/api/test_embedding_endpoint",
                    serde_json::json!({ "endpoint": base_endpoint, "model": "test-model" }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("success response"),
        )
        .await;
        assert_eq!(
            success_json["data"]["kind"],
            Value::String("ok".to_string())
        );
        assert_eq!(success_json["data"]["dimensions"], Value::from(3));

        let localhost_success_json = read_ok_json(
            app.clone()
                .oneshot(valid_json_request(
                    "/api/test_embedding_endpoint",
                    serde_json::json!({ "endpoint": localhost_endpoint, "model": "test-model" }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("localhost success response"),
        )
        .await;
        assert_eq!(
            localhost_success_json["data"]["kind"],
            Value::String("ok".to_string())
        );
        assert_eq!(localhost_success_json["data"]["dimensions"], Value::from(3));

        let redirect_json = read_ok_json(
            app.clone()
                .oneshot(valid_json_request(
                    "/api/test_embedding_endpoint",
                    serde_json::json!({ "endpoint": base_endpoint, "model": "redirect-me" }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("redirect response"),
        )
        .await;
        assert_eq!(
            redirect_json["data"]["kind"],
            Value::String("http_error".to_string())
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(second_hits.load(Ordering::SeqCst), 0);

        let too_large_json = read_ok_json(
            app.clone()
                .oneshot(valid_json_request(
                    "/api/test_embedding_endpoint",
                    serde_json::json!({ "endpoint": base_endpoint, "model": "too-large" }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("content-length too large response"),
        )
        .await;
        assert_eq!(
            too_large_json["data"]["kind"],
            Value::String("endpoint_unsupported".to_string())
        );
        assert_eq!(
            too_large_json["data"]["preview"],
            Value::String("response too large".to_string())
        );

        let chunked_too_large_json = read_ok_json(
            app.clone()
                .oneshot(valid_json_request(
                    "/api/test_embedding_endpoint",
                    serde_json::json!({ "endpoint": format!("http://127.0.0.1:{}/large", first_addr.port()), "model": "chunked" }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("chunked too large response"),
        )
        .await;
        assert_eq!(
            chunked_too_large_json["data"]["kind"],
            Value::String("endpoint_unsupported".to_string())
        );
        assert_eq!(
            chunked_too_large_json["data"]["preview"],
            Value::String("response too large".to_string())
        );

        let leak_response = app
            .oneshot(valid_json_request(
                "/api/test_embedding_endpoint",
                serde_json::json!({
                    "endpoint": format!("http://127.0.0.1:{}/v1", first_addr.port()),
                    "model": "leak-me",
                    "apiKey": secret,
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("leak response");
        let leak_body = to_bytes(leak_response.into_body(), usize::MAX)
            .await
            .expect("leak body");
        let leak_text = String::from_utf8(leak_body.to_vec()).expect("leak utf8");
        assert!(!leak_text.contains(secret));
        assert!(!leak_text.contains("Authorization: Bearer"));
        assert!(!leak_text.contains("Bearer sk-test"));

        first_handle.abort();
        second_handle.abort();
    }

    #[tokio::test]
    async fn user_memory_phase_two_routes_require_valid_token() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        create_user_memory_test_db(&db_path, 3, 2);

        let app = build_router(test_state(Some(db_path), 1422));
        let requests = [
            ("/api/get_user_memories", serde_json::json!({ "limit": 10 })),
            (
                "/api/get_user_memory_candidates",
                serde_json::json!({ "limit": 10 }),
            ),
            ("/api/dismiss_user_memory", serde_json::json!({ "id": 1 })),
            ("/api/delete_user_memory", serde_json::json!({ "id": 2 })),
            (
                "/api/update_user_memory_content",
                serde_json::json!({ "id": 3, "content": "updated" }),
            ),
            (
                "/api/delete_user_memory_candidate",
                serde_json::json!({ "id": 1 }),
            ),
            (
                "/api/promote_user_memory_candidate",
                serde_json::json!({ "id": 2 }),
            ),
        ];

        for (uri, payload) in requests {
            let forbidden = app
                .clone()
                .oneshot(valid_json_request(uri, payload.clone(), None, false))
                .await
                .expect("response without token");
            assert_eq!(forbidden.status(), StatusCode::FORBIDDEN, "{uri}");

            let allowed = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("response with token");
            assert_eq!(allowed.status(), StatusCode::OK, "{uri}");
        }
    }

    #[tokio::test]
    async fn user_memory_phase_two_read_bounds_and_validation_hold() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        create_user_memory_test_db(&db_path, 600, 250);
        let app = build_router(test_state(Some(db_path), 1422));

        let default_memories = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_user_memories",
                serde_json::json!({}),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("default memories");
        let default_memories_json = read_ok_json(default_memories).await;
        assert_eq!(
            default_memories_json["data"]
                .as_array()
                .expect("array")
                .len(),
            200
        );

        let max_memories = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_user_memories",
                serde_json::json!({ "limit": 500, "status": "active" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("max memories");
        let max_memories_json = read_ok_json(max_memories).await;
        let max_memories_rows = max_memories_json["data"].as_array().expect("array");
        assert_eq!(max_memories_rows.len(), 300);
        assert!(max_memories_rows
            .iter()
            .all(|row| row["status"] == "active"));

        let default_candidates = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_user_memory_candidates",
                serde_json::json!({}),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("default candidates");
        let default_candidates_json = read_ok_json(default_candidates).await;
        assert_eq!(
            default_candidates_json["data"]
                .as_array()
                .expect("array")
                .len(),
            100
        );

        let max_candidates = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_user_memory_candidates",
                serde_json::json!({ "limit": 200 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("max candidates");
        let max_candidates_json = read_ok_json(max_candidates).await;
        assert_eq!(
            max_candidates_json["data"].as_array().expect("array").len(),
            200
        );

        for (uri, payload) in [
            (
                "/api/get_user_memories",
                serde_json::json!({ "status": "weird", "limit": 10 }),
            ),
            ("/api/get_user_memories", serde_json::json!({ "limit": 0 })),
            (
                "/api/get_user_memories",
                serde_json::json!({ "limit": 501 }),
            ),
            (
                "/api/get_user_memory_candidates",
                serde_json::json!({ "limit": 0 }),
            ),
            (
                "/api/get_user_memory_candidates",
                serde_json::json!({ "limit": 201 }),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("bad request");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }

        let oversize_read = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_user_memories",
                serde_json::json!({ "padding": "x".repeat(USER_MEMORY_READ_BODY_MAX_BYTES) }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("oversize read response");
        assert_eq!(oversize_read.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn user_memory_phase_two_id_mutations_reject_invalid_and_stale_ids() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        create_user_memory_test_db(&db_path, 1, 1);
        let app = build_router(test_state(Some(db_path), 1422));

        for uri in [
            "/api/dismiss_user_memory",
            "/api/delete_user_memory",
            "/api/delete_user_memory_candidate",
            "/api/promote_user_memory_candidate",
        ] {
            for payload in [
                serde_json::json!({ "id": 0 }),
                serde_json::json!({ "id": -1 }),
                serde_json::json!({}),
            ] {
                let response = app
                    .clone()
                    .oneshot(valid_json_request(
                        uri,
                        payload,
                        Some(TEST_LOCAL_AUTH_TOKEN),
                        false,
                    ))
                    .await
                    .expect("invalid id response");
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            }

            let stale = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    serde_json::json!({ "id": 99999 }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("stale response");
            assert_eq!(stale.status(), StatusCode::BAD_REQUEST, "{uri}");
            let stale_json = read_error_json(stale).await;
            assert_eq!(stale_json["ok"], Value::Bool(false));
        }
    }

    #[tokio::test]
    async fn user_memory_phase_two_update_content_validation_and_success() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        create_user_memory_test_db(&db_path, 1, 0);
        let app = build_router(test_state(Some(db_path.clone()), 1422));

        for payload in [
            serde_json::json!({ "id": 1, "content": "" }),
            serde_json::json!({ "id": 1, "content": "   \n\t" }),
            serde_json::json!({ "id": 1, "content": "x".repeat(USER_MEMORY_CONTENT_MAX_BYTES + 1) }),
            serde_json::json!({}),
        ] {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    "/api/update_user_memory_content",
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("invalid content response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let body_too_large = app
            .clone()
            .oneshot(valid_json_request(
                "/api/update_user_memory_content",
                serde_json::json!({
                    "id": 1,
                    "content": "x".repeat(USER_MEMORY_CONTENT_BODY_MAX_BYTES),
                    "padding": "y".repeat(256)
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("body too large response");
        assert_eq!(body_too_large.status(), StatusCode::BAD_REQUEST);

        let success = app
            .clone()
            .oneshot(valid_json_request(
                "/api/update_user_memory_content",
                serde_json::json!({ "id": 1, "content": "  exact preserved  " }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("success response");
        assert_eq!(success.status(), StatusCode::OK);

        let conn = rusqlite::Connection::open(&db_path).expect("reopen");
        let stored: String = conn
            .query_row(
                "SELECT content FROM user_memories WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("stored content");
        assert_eq!(stored, "  exact preserved  ");
        assert_eq!(user_profile_version_from_db(&conn), 1);
    }

    #[tokio::test]
    async fn user_memory_phase_two_promotion_enforces_side_effect_semantics() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        create_user_memory_test_db(&db_path, 0, 1);
        let app = build_router(test_state(Some(db_path.clone()), 1422));

        let success = app
            .clone()
            .oneshot(valid_json_request(
                "/api/promote_user_memory_candidate",
                serde_json::json!({ "id": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("promote response");
        assert_eq!(success.status(), StatusCode::OK);

        let conn = rusqlite::Connection::open(&db_path).expect("reopen");
        let row: (String, String) = conn
            .query_row(
                "SELECT content, status FROM user_memories WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("memory row");
        assert_eq!(row, ("candidate 1".to_string(), "active".to_string()));
        let candidate_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM user_memory_candidates", [], |row| {
                row.get(0)
            })
            .expect("candidate count");
        assert_eq!(candidate_count, 0);
        assert_eq!(user_profile_version_from_db(&conn), 1);

        let stale = app
            .clone()
            .oneshot(valid_json_request(
                "/api/promote_user_memory_candidate",
                serde_json::json!({ "id": 999 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("stale promote response");
        assert_eq!(stale.status(), StatusCode::BAD_REQUEST);

        let oversize_dir = tempdir().expect("temp dir");
        let oversize_db = oversize_dir.path().join("context.db");
        create_user_memory_test_db(&oversize_db, 0, 0);
        let oversize_conn = rusqlite::Connection::open(&oversize_db).expect("open oversize db");
        oversize_conn
            .execute(
                "INSERT INTO user_memory_candidates (content, session_id, source_compartment_start, source_compartment_end, created_at)
                 VALUES (?1, 'session-oversize', NULL, NULL, 999)",
                rusqlite::params!["x".repeat(USER_MEMORY_CONTENT_MAX_BYTES + 1)],
            )
            .expect("insert oversize candidate");
        drop(oversize_conn);

        let oversize_app = build_router(test_state(Some(oversize_db.clone()), 1422));
        let oversize = oversize_app
            .oneshot(valid_json_request(
                "/api/promote_user_memory_candidate",
                serde_json::json!({ "id": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("oversize promote response");
        assert_eq!(oversize.status(), StatusCode::BAD_REQUEST);

        let oversize_conn = rusqlite::Connection::open(&oversize_db).expect("reopen oversize db");
        let memory_count: i64 = oversize_conn
            .query_row("SELECT COUNT(*) FROM user_memories", [], |row| row.get(0))
            .expect("memory count");
        assert_eq!(memory_count, 0);
        let candidate_count: i64 = oversize_conn
            .query_row("SELECT COUNT(*) FROM user_memory_candidates", [], |row| {
                row.get(0)
            })
            .expect("candidate count");
        assert_eq!(candidate_count, 1);
        assert_eq!(user_profile_version_from_db(&oversize_conn), 0);
    }

    #[test]
    fn config_phase_three_routes_have_exact_access_and_unapproved_routes_absent() {
        let expected = [
            ("get_config", CommandAccess::SensitiveRead),
            ("save_config", CommandAccess::Write),
            ("read_pi_config", CommandAccess::SensitiveRead),
            ("write_pi_config", CommandAccess::Write),
            ("get_project_configs", CommandAccess::SensitiveRead),
            ("save_project_config", CommandAccess::Write),
        ];

        for (command, access) in expected {
            let spec = find_command_spec(command).expect("route present");
            assert_eq!(spec.access, access, "{command}");
        }

        for command in [
            "list_processes",
            "enqueue_dream",
            "delete_dream_queue_entry",
            "invoke_backend_command",
        ] {
            assert!(
                find_command_spec(command).is_none(),
                "{command} should stay absent"
            );
        }
    }

    #[test]
    fn logs_phase_four_a_route_has_exact_access_and_regression_routes_stay_absent() {
        let spec = find_command_spec("get_log_entries").expect("route present");
        assert_eq!(spec.access, CommandAccess::SensitiveRead);

        for command in [
            "get_cache_events",
            "get_session_cache_stats",
            "get_session_cache_stats_from_db",
            "get_context_token_breakdown",
            "enqueue_dream",
            "delete_dream_queue_entry",
            "enumerate_projects",
            "enumerate_memory_projects",
            "get_session_facts",
            "get_session_notes",
        ] {
            assert!(
                find_command_spec(command).is_none(),
                "{command} should stay absent"
            );
        }
    }

    #[tokio::test]
    async fn get_log_entries_requires_valid_token_and_missing_log_is_ok() {
        let _guard = LOG_ROUTE_TEST_LOCK.lock().expect("log route test lock");
        let app = build_router(test_state(None, 1422));
        let forbidden = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_log_entries",
                serde_json::json!({ "maxLines": 5 }),
                None,
                false,
            ))
            .await
            .expect("response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .oneshot(valid_json_request(
                "/api/get_log_entries",
                serde_json::json!({ "maxLines": 5 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_log_entries_validates_body_size_and_max_lines_shape() {
        let app = build_router(test_state(None, 1422));

        for payload in [
            serde_json::json!({}),
            serde_json::json!({ "maxLines": null }),
            serde_json::json!({ "maxLines": 500 }),
        ] {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    "/api/get_log_entries",
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        }

        for payload in [
            serde_json::json!({ "extra": true }),
            serde_json::json!({ "maxLines": "5" }),
            serde_json::json!({ "maxLines": 5.5 }),
            serde_json::json!({ "maxLines": true }),
            serde_json::json!({ "maxLines": { "value": 5 } }),
            serde_json::json!({ "maxLines": [5] }),
            serde_json::json!({ "maxLines": 0 }),
            serde_json::json!({ "maxLines": -1 }),
            serde_json::json!({ "maxLines": 501 }),
        ] {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    "/api/get_log_entries",
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("bad response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let body_too_large = app
            .oneshot(valid_json_request(
                "/api/get_log_entries",
                serde_json::json!({ "padding": "x".repeat(LOG_ENTRIES_READ_BODY_MAX_BYTES) }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("oversize response");
        assert_eq!(body_too_large.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn config_phase_three_routes_require_valid_token() {
        let _guard = CONFIG_TEST_LOCK.lock().expect("config test lock");
        let fixture = ConfigTestFixture::new();
        fixture.set_env();

        let app = build_router(test_state(None, 1422));
        let requests = [
            ("/api/get_config", serde_json::json!({ "source": "user" })),
            (
                "/api/save_config",
                serde_json::json!({ "source": "user", "content": "{}" }),
            ),
            ("/api/read_pi_config", serde_json::json!({})),
            (
                "/api/write_pi_config",
                serde_json::json!({ "content": "{}" }),
            ),
            (
                "/api/get_project_configs",
                serde_json::json!({ "limit": 10 }),
            ),
            (
                "/api/save_project_config",
                serde_json::json!({
                    "projectPath": fixture.root_project_dir.to_string_lossy(),
                    "content": "{\n  \"browser\": true\n}"
                }),
            ),
        ];

        for (uri, payload) in requests {
            let forbidden = app
                .clone()
                .oneshot(valid_json_request(uri, payload.clone(), None, false))
                .await
                .expect("response without token");
            assert_eq!(forbidden.status(), StatusCode::FORBIDDEN, "{uri}");

            let allowed = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("response with token");
            assert_eq!(allowed.status(), StatusCode::OK, "{uri}");
        }
    }

    #[tokio::test]
    async fn config_phase_three_validation_rejects_bad_source_body_and_size() {
        let _guard = CONFIG_TEST_LOCK.lock().expect("config test lock");
        let fixture = ConfigTestFixture::new();
        fixture.set_env();

        let app = build_router(test_state(None, 1422));
        let cases = [
            (
                "/api/get_config",
                serde_json::json!({ "source": "bogus" }),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/get_config",
                serde_json::json!({ "source": "project" }),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/save_config",
                serde_json::json!({ "source": "project", "content": "{}" }),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/read_pi_config",
                serde_json::json!({ "unexpected": true }),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/get_project_configs",
                serde_json::json!({ "limit": 0 }),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/get_project_configs",
                serde_json::json!({ "limit": (PROJECT_CONFIGS_LIMIT_MAX as i64) + 1 }),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/save_project_config",
                serde_json::json!({
                    "projectPath": fixture.root_project_dir.to_string_lossy(),
                    "content": "x".repeat(CONFIG_CONTENT_MAX_BYTES + 1)
                }),
                StatusCode::BAD_REQUEST,
            ),
        ];

        for (uri, payload, status) in cases {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("bad request response");
            assert_eq!(response.status(), status, "{uri}");
        }

        let malformed = app
            .clone()
            .oneshot(valid_raw_json_request(
                "/api/get_config",
                "{",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("malformed response");
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

        let oversized_read = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_project_configs",
                serde_json::json!({ "padding": "x".repeat(CONFIG_READ_BODY_MAX_BYTES) }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("oversized read response");
        assert_eq!(oversized_read.status(), StatusCode::BAD_REQUEST);

        let oversized_write = app
            .clone()
            .oneshot(valid_json_request(
                "/api/save_config",
                serde_json::json!({
                    "source": "user",
                    "content": "{}",
                    "padding": "x".repeat(CONFIG_WRITE_BODY_MAX_BYTES)
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("oversized write response");
        assert_eq!(oversized_write.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn config_phase_three_user_and_pi_reads_handle_missing_and_oversized_files() {
        let _guard = CONFIG_TEST_LOCK.lock().expect("config test lock");
        let fixture = ConfigTestFixture::new();
        fixture.set_env();

        let app = build_router(test_state(None, 1422));

        let missing_user = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_config",
                serde_json::json!({ "source": "user" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("missing user response");
        let missing_user_json = read_ok_json(missing_user).await;
        assert_eq!(missing_user_json["data"]["exists"], Value::Bool(false));
        assert_eq!(
            missing_user_json["data"]["content"],
            Value::String(String::new())
        );

        let missing_pi = app
            .clone()
            .oneshot(valid_empty_body_request(
                "/api/read_pi_config",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("missing pi response");
        let missing_pi_json = read_ok_json(missing_pi).await;
        assert_eq!(missing_pi_json["data"]["exists"], Value::Bool(false));
        assert_eq!(
            missing_pi_json["data"]["content"],
            Value::String(String::new())
        );

        fs::create_dir_all(
            fixture
                .user_config_path
                .parent()
                .expect("user config parent"),
        )
        .expect("create user config parent");
        fs::write(
            &fixture.user_config_path,
            "x".repeat(CONFIG_CONTENT_MAX_BYTES + 1),
        )
        .expect("write oversized user config");
        let oversized_user = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_config",
                serde_json::json!({ "source": "user" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("oversized user response");
        assert_eq!(oversized_user.status(), StatusCode::BAD_REQUEST);

        fs::create_dir_all(fixture.pi_config_path.parent().expect("pi config parent"))
            .expect("create pi config parent");
        fs::write(
            &fixture.pi_config_path,
            "x".repeat(CONFIG_CONTENT_MAX_BYTES + 1),
        )
        .expect("write oversized pi config");
        let oversized_pi = app
            .clone()
            .oneshot(valid_empty_body_request(
                "/api/read_pi_config",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("oversized pi response");
        assert_eq!(oversized_pi.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn config_phase_three_unreadable_existing_config_errors() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = CONFIG_TEST_LOCK.lock().expect("config test lock");
        let fixture = ConfigTestFixture::new();
        fixture.set_env();

        fs::create_dir_all(
            fixture
                .user_config_path
                .parent()
                .expect("user config parent"),
        )
        .expect("create user config parent");
        fs::write(&fixture.user_config_path, "{\n  \"locked\": true\n}")
            .expect("write user config");
        let mut perms = fs::metadata(&fixture.user_config_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&fixture.user_config_path, perms).expect("chmod 000");

        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_config",
                serde_json::json!({ "source": "user" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("unreadable response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = read_error_json(response).await;
        assert_eq!(json["ok"], Value::Bool(false));

        let mut restore = fs::metadata(&fixture.user_config_path)
            .expect("metadata restore")
            .permissions();
        restore.set_mode(0o644);
        fs::set_permissions(&fixture.user_config_path, restore).expect("chmod restore");
    }

    #[tokio::test]
    async fn config_phase_three_project_path_security_and_existing_target_rules_hold() {
        let _guard = CONFIG_TEST_LOCK.lock().expect("config test lock");
        let fixture = ConfigTestFixture::new();
        fixture.set_env();

        let app = build_router(test_state(None, 1422));

        for payload in [
            serde_json::json!({ "source": "project" }),
            serde_json::json!({ "source": "project", "projectPath": "relative/path" }),
            serde_json::json!({ "source": "project", "projectPath": fixture.temp.path().join("missing").to_string_lossy() }),
            serde_json::json!({ "source": "project", "projectPath": fixture.unknown_project_dir.to_string_lossy() }),
        ] {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    "/api/get_config",
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("bad project path response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let root_read = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_config",
                serde_json::json!({
                    "source": "project",
                    "projectPath": fixture.root_project_dir.to_string_lossy()
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("root read response");
        let root_read_json = read_ok_json(root_read).await;
        assert_eq!(
            root_read_json["data"]["path"],
            Value::String(fixture.root_config_path.to_string_lossy().to_string())
        );
        assert_eq!(
            root_read_json["data"]["content"],
            Value::String("{\n  \"root\": true\n}".to_string())
        );

        let root_save = app
            .clone()
            .oneshot(valid_json_request(
                "/api/save_project_config",
                serde_json::json!({
                    "projectPath": fixture.root_project_dir.to_string_lossy(),
                    "content": "{\n  \"root\": \"updated\"\n}"
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("root save response");
        assert_eq!(root_save.status(), StatusCode::OK);
        assert_eq!(
            fs::read_to_string(&fixture.root_config_path).expect("read root config"),
            "{\n  \"root\": \"updated\"\n}"
        );

        let alt_read = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_config",
                serde_json::json!({
                    "source": "project",
                    "projectPath": fixture.alt_project_dir.to_string_lossy()
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("alt read response");
        let alt_read_json = read_ok_json(alt_read).await;
        assert_eq!(
            alt_read_json["data"]["path"],
            Value::String(fixture.alt_config_path.to_string_lossy().to_string())
        );
        assert_eq!(
            alt_read_json["data"]["content"],
            Value::String("{\n  \"alt\": true\n}".to_string())
        );

        let alt_save = app
            .clone()
            .oneshot(valid_json_request(
                "/api/save_project_config",
                serde_json::json!({
                    "projectPath": fixture.alt_project_dir.to_string_lossy(),
                    "content": "{\n  \"alt\": \"updated\"\n}"
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("alt save response");
        assert_eq!(alt_save.status(), StatusCode::OK);
        assert_eq!(
            fs::read_to_string(&fixture.alt_config_path).expect("read alt config"),
            "{\n  \"alt\": \"updated\"\n}"
        );

        let neither = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_config",
                serde_json::json!({
                    "source": "project",
                    "projectPath": fixture.no_config_project_dir.to_string_lossy()
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("no config response");
        assert_eq!(neither.status(), StatusCode::BAD_REQUEST);

        let symlink_escape = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_config",
                serde_json::json!({
                    "source": "project",
                    "projectPath": fixture.symlink_project_dir.to_string_lossy()
                }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("symlink escape response");
        assert_eq!(symlink_escape.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn config_phase_three_project_configs_listing_is_sorted_and_bounded() {
        let _guard = CONFIG_TEST_LOCK.lock().expect("config test lock");
        let fixture = ConfigTestFixture::new();
        fixture.set_env();

        let app = build_router(test_state(None, 1422));
        let response = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_project_configs",
                serde_json::json!({ "limit": 2 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("project configs response");
        let json = read_ok_json(response).await;
        let rows = json["data"].as_array().expect("rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["project_name"], Value::String("Alpha".to_string()));
        assert_eq!(rows[1]["project_name"], Value::String("zeta".to_string()));

        let worktrees = rows
            .iter()
            .map(|row| row["worktree"].as_str().expect("worktree").to_string())
            .collect::<Vec<_>>();
        assert!(worktrees.iter().all(|path| {
            path == &fixture.alt_project_dir.to_string_lossy()
                || path == &fixture.root_project_dir.to_string_lossy()
                || path == &fixture.alt_project_dir.to_string_lossy()
        }));
        assert!(!worktrees.contains(&fixture.no_config_project_dir.to_string_lossy().to_string()));
    }

    #[tokio::test]
    async fn session_cache_phase_one_routes_require_valid_token() {
        let _guard = PI_TEST_LOCK.lock().expect("pi test lock");
        let dir = tempdir().expect("temp dir");
        let session_id = "pi-token-session";
        write_pi_session_fixture(&dir, session_id, 4).expect("write fixture");
        crate::pi_sessions::clear_caches_for_tests();
        crate::pi_sessions::set_test_root_for_tests(dir.path().to_path_buf());

        let app = build_router(test_state(None, 1422));
        let requests = [
            (
                "/api/get_session_messages",
                serde_json::json!({ "harness": "pi", "sessionId": session_id }),
            ),
            (
                "/api/get_session_cache_events",
                serde_json::json!({ "harness": "pi", "sessionId": session_id, "limit": 10 }),
            ),
            (
                "/api/get_session_cache_events_by_turns",
                serde_json::json!({ "harness": "pi", "sessionId": session_id, "targetTurns": 10 }),
            ),
            (
                "/api/get_cache_events_from_db",
                serde_json::json!({ "limit": 10, "sinceTimestamp": 0 }),
            ),
        ];

        for (uri, payload) in requests.iter() {
            let forbidden = app
                .clone()
                .oneshot(valid_json_request(uri, payload.clone(), None, false))
                .await
                .expect("response without token");
            assert_eq!(forbidden.status(), StatusCode::FORBIDDEN, "{uri}");

            let allowed = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    payload.clone(),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("response with token");
            assert_eq!(allowed.status(), StatusCode::OK, "{uri}");
        }

        crate::pi_sessions::clear_caches_for_tests();
    }

    #[tokio::test]
    async fn session_cache_phase_one_validation_rejects_bad_requests() {
        let app = build_router(test_state(None, 1422));
        let too_long = "x".repeat(513);
        let cases = vec![
            (
                "/api/get_session_messages",
                serde_json::json!({ "harness": "pi", "sessionId": "   " }),
            ),
            (
                "/api/get_session_messages",
                serde_json::json!({ "harness": "bogus", "sessionId": "s1" }),
            ),
            (
                "/api/get_session_messages",
                serde_json::json!({ "harness": "pi", "sessionId": too_long }),
            ),
            (
                "/api/get_session_messages",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "limit": 0 }),
            ),
            (
                "/api/get_session_messages",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "limit": -1 }),
            ),
            (
                "/api/get_session_messages",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "limit": 2001 }),
            ),
            (
                "/api/get_session_cache_events",
                serde_json::json!({ "harness": "pi", "sessionId": "s1" }),
            ),
            (
                "/api/get_session_cache_events",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "limit": 0 }),
            ),
            (
                "/api/get_session_cache_events",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "limit": -5 }),
            ),
            (
                "/api/get_session_cache_events",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "limit": 601 }),
            ),
            (
                "/api/get_session_cache_events_by_turns",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "targetTurns": 0 }),
            ),
            (
                "/api/get_session_cache_events_by_turns",
                serde_json::json!({ "harness": "pi", "sessionId": "s1", "targetTurns": 201 }),
            ),
            (
                "/api/get_cache_events_from_db",
                serde_json::json!({ "limit": 0 }),
            ),
            (
                "/api/get_cache_events_from_db",
                serde_json::json!({ "limit": -1 }),
            ),
            (
                "/api/get_cache_events_from_db",
                serde_json::json!({ "limit": 201 }),
            ),
            (
                "/api/get_cache_events_from_db",
                serde_json::json!({ "limit": 10, "sinceTimestamp": -1 }),
            ),
        ];

        for (uri, payload) in cases {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    uri,
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[tokio::test]
    async fn session_cache_phase_one_cap_behavior_is_bounded() {
        let _guard = PI_TEST_LOCK.lock().expect("pi test lock");
        let dir = tempdir().expect("temp dir");
        let session_id = "pi-cap-session";
        write_pi_session_fixture(&dir, session_id, 2505).expect("write fixture");
        crate::pi_sessions::clear_caches_for_tests();
        crate::pi_sessions::set_test_root_for_tests(dir.path().to_path_buf());

        let app = build_router(test_state(None, 1422));

        let messages = read_ok_json(
            app.clone()
                .oneshot(valid_json_request(
                    "/api/get_session_messages",
                    serde_json::json!({ "harness": "pi", "sessionId": session_id }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("messages response"),
        )
        .await;
        let message_rows = messages["data"].as_array().expect("message rows");
        assert_eq!(message_rows.len(), SESSION_MESSAGES_LIMIT_DEFAULT);
        assert!(message_rows.iter().all(|row| row["raw_json"].is_null()));

        let cache_events = read_ok_json(
            app.clone()
                .oneshot(valid_json_request(
                    "/api/get_session_cache_events",
                    serde_json::json!({ "harness": "pi", "sessionId": session_id, "limit": 600 }),
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("cache events response"),
        )
        .await;
        let cache_rows = cache_events["data"].as_array().expect("cache rows");
        assert!(cache_rows.len() <= SESSION_CACHE_EVENTS_LIMIT_MAX);

        let global_events = read_ok_json(
            app.oneshot(valid_json_request(
                "/api/get_cache_events_from_db",
                serde_json::json!({ "limit": 200 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("global cache response"),
        )
        .await;
        let global_rows = global_events["data"].as_array().expect("global rows");
        assert!(global_rows.len() <= GLOBAL_CACHE_EVENTS_LIMIT_MAX * 10);

        crate::pi_sessions::clear_caches_for_tests();
    }

    #[test]
    fn get_memories_limit_is_clamped_to_max() {
        assert_eq!(clamp_get_memories_limit(None), 100);
        assert_eq!(clamp_get_memories_limit(Some(999)), GET_MEMORIES_LIMIT_MAX);
        assert_eq!(clamp_get_memories_limit(Some(400)), 400);
    }

    #[test]
    fn list_sessions_paged_limit_is_clamped_to_max() {
        let filter = db::SessionFilter {
            limit: Some(999),
            ..Default::default()
        };
        let clamped = clamp_session_filter_limit(Some(filter)).expect("filter");
        assert_eq!(clamped.limit, Some(LIST_SESSIONS_LIMIT_MAX));
    }

    #[tokio::test]
    async fn bulk_memory_operations_reject_more_than_hundred_ids() {
        let ids: Vec<i64> = (0..101).collect();
        let app = build_router(test_state(None, 1422));

        let update_response = app
            .clone()
            .oneshot(valid_json_request(
                "/api/bulk_update_memory_status",
                serde_json::json!({ "memoryIds": ids, "status": "archived" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                true,
            ))
            .await
            .expect("response");
        assert_eq!(update_response.status(), StatusCode::BAD_REQUEST);

        let delete_response = app
            .oneshot(valid_json_request(
                "/api/bulk_delete_memory",
                serde_json::json!({ "memoryIds": (0..101).collect::<Vec<i64>>() }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                true,
            ))
            .await
            .expect("response");
        assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_subagent_invocations_returns_success_with_valid_token() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute(
            "CREATE TABLE subagent_invocations (
                id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                harness TEXT NOT NULL,
                subagent TEXT NOT NULL,
                task TEXT,
                provider_id TEXT,
                model_id TEXT,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                status TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cache_read_tokens INTEGER NOT NULL,
                cache_write_tokens INTEGER NOT NULL,
                error TEXT,
                parent_invocation_id INTEGER
            )",
            [],
        )
        .expect("create subagent_invocations");
        conn.execute(
            "INSERT INTO subagent_invocations (
                id, session_id, harness, subagent, task, provider_id, model_id,
                started_at, ended_at, status, input_tokens, output_tokens,
                cache_read_tokens, cache_write_tokens, error, parent_invocation_id
            ) VALUES (?1, ?2, 'opencode', 'historian', 'task', NULL, NULL, 1000, NULL,
                'completed', 10, 20, 1, 2, NULL, NULL)",
            rusqlite::params![1_i64, "sess-1"],
        )
        .expect("insert row");

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_subagent_invocations",
                serde_json::json!({ "sessionId": "sess-1" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["ok"], Value::Bool(true));
        assert_eq!(json["data"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            json["data"][0]["session_id"],
            Value::String("sess-1".into())
        );
    }

    #[tokio::test]
    async fn get_subagent_totals_by_subagent_result_count_is_capped() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute(
            "CREATE TABLE subagent_invocations (
                id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                harness TEXT NOT NULL,
                subagent TEXT NOT NULL,
                task TEXT,
                provider_id TEXT,
                model_id TEXT,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                status TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cache_read_tokens INTEGER NOT NULL,
                cache_write_tokens INTEGER NOT NULL,
                error TEXT,
                parent_invocation_id INTEGER
            )",
            [],
        )
        .expect("create subagent_invocations");
        for i in 0..105_i64 {
            conn.execute(
                "INSERT INTO subagent_invocations (
                    id, session_id, harness, subagent, task, provider_id, model_id,
                    started_at, ended_at, status, input_tokens, output_tokens,
                    cache_read_tokens, cache_write_tokens, error, parent_invocation_id
                ) VALUES (?1, ?2, 'opencode', ?3, 'task', NULL, NULL, ?4, NULL,
                    'completed', 1, 1, 0, 0, NULL, NULL)",
                rusqlite::params![
                    i + 1,
                    "sess-totals",
                    format!("subagent-{i:03}"),
                    1000_i64 + i
                ],
            )
            .expect("insert row");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_subagent_totals_by_subagent",
                serde_json::json!({ "sessionId": "sess-totals" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json["data"].as_array().map(Vec::len),
            Some(SUBAGENT_TOTALS_LIMIT_MAX)
        );
    }

    #[tokio::test]
    async fn get_project_key_files_rejects_without_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_project_key_files",
                serde_json::json!({ "projectPath": "/tmp/project" }),
                None,
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_project_key_files_rejects_malformed_body() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/get_project_key_files")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::ORIGIN, "http://127.0.0.1:1420")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(LOCAL_AUTH_TOKEN_HEADER, TEST_LOCAL_AUTH_TOKEN)
                    .body(Body::from("{"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_project_key_files_result_count_is_capped() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute_batch(
            "CREATE TABLE project_key_files (
                project_path TEXT NOT NULL,
                path TEXT NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT,
                local_token_estimate INTEGER,
                generated_at INTEGER NOT NULL,
                generated_by_model TEXT,
                generation_config_hash TEXT,
                stale_reason TEXT
            );
            CREATE TABLE project_key_files_version (
                project_path TEXT NOT NULL,
                version INTEGER NOT NULL
            );",
        )
        .expect("create key file tables");
        conn.execute(
            "INSERT INTO project_key_files_version (project_path, version) VALUES (?1, ?2)",
            rusqlite::params!["/tmp/project", 7_i64],
        )
        .expect("insert version");
        for i in 0..30_i64 {
            conn.execute(
                "INSERT INTO project_key_files (
                    project_path, path, content, content_hash, local_token_estimate,
                    generated_at, generated_by_model, generation_config_hash, stale_reason
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    "/tmp/project",
                    format!("file-{i:02}.md"),
                    format!("content-{i}"),
                    format!("hash-{i}"),
                    10_i64,
                    1000_i64 + i,
                    "model",
                    "cfg",
                    Option::<String>::None
                ],
            )
            .expect("insert key file");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_project_key_files",
                serde_json::json!({ "projectPath": "/tmp/project" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json["data"].as_array().map(Vec::len),
            Some(PROJECT_KEY_FILES_LIMIT_MAX)
        );
    }

    #[tokio::test]
    async fn get_compartments_accepts_camel_case_session_id() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute(
            "CREATE TABLE compartments (
                id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                start_message INTEGER NOT NULL,
                end_message INTEGER NOT NULL,
                start_message_id TEXT,
                end_message_id TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                importance INTEGER,
                episode_type TEXT,
                p1 TEXT,
                p2 TEXT,
                p3 TEXT,
                p4 TEXT,
                legacy INTEGER
            )",
            [],
        )
        .expect("create compartments");
        conn.execute(
            "INSERT INTO compartments (
                id, session_id, sequence, start_message, end_message, start_message_id,
                end_message_id, title, content, created_at, importance, episode_type,
                p1, p2, p3, p4, legacy
            ) VALUES (?1, ?2, 1, 1, 2, NULL, NULL, 'Compartment', 'Summary', 1000, 50,
                'design', NULL, NULL, NULL, NULL, 0)",
            rusqlite::params![1_i64, "sess-comp"],
        )
        .expect("insert compartment");

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_compartments",
                serde_json::json!({ "sessionId": "sess-comp" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["data"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            json["data"][0]["session_id"],
            Value::String("sess-comp".into())
        );
    }

    #[tokio::test]
    async fn get_compartments_result_count_is_capped() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute(
            "CREATE TABLE compartments (
                id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                start_message INTEGER NOT NULL,
                end_message INTEGER NOT NULL,
                start_message_id TEXT,
                end_message_id TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                importance INTEGER,
                episode_type TEXT,
                p1 TEXT,
                p2 TEXT,
                p3 TEXT,
                p4 TEXT,
                legacy INTEGER
            )",
            [],
        )
        .expect("create compartments");
        for i in 0..205_i64 {
            conn.execute(
                "INSERT INTO compartments (
                    id, session_id, sequence, start_message, end_message, start_message_id,
                    end_message_id, title, content, created_at, importance, episode_type,
                    p1, p2, p3, p4, legacy
                ) VALUES (?1, ?2, ?3, 1, 2, NULL, NULL, ?4, ?5, ?6, 50,
                    'design', NULL, NULL, NULL, NULL, 0)",
                rusqlite::params![
                    i + 1,
                    "sess-cap",
                    i + 1,
                    format!("Compartment {i}"),
                    format!("Summary {i}"),
                    1000_i64 + i
                ],
            )
            .expect("insert compartment");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_compartments",
                serde_json::json!({ "sessionId": "sess-cap" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json["data"].as_array().map(Vec::len),
            Some(COMPARTMENTS_LIMIT_MAX)
        );
    }

    #[tokio::test]
    async fn get_subagent_invocations_clamps_result_count() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        conn.execute(
            "CREATE TABLE subagent_invocations (
                id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                harness TEXT NOT NULL,
                subagent TEXT NOT NULL,
                task TEXT,
                provider_id TEXT,
                model_id TEXT,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                status TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cache_read_tokens INTEGER NOT NULL,
                cache_write_tokens INTEGER NOT NULL,
                error TEXT,
                parent_invocation_id INTEGER
            )",
            [],
        )
        .expect("create subagent_invocations");
        for id in 0..(SUBAGENT_INVOCATIONS_LIMIT_MAX as i64 + 20) {
            conn.execute(
                "INSERT INTO subagent_invocations (
                    id, session_id, harness, subagent, task, provider_id, model_id,
                    started_at, ended_at, status, input_tokens, output_tokens,
                    cache_read_tokens, cache_write_tokens, error, parent_invocation_id
                ) VALUES (?1, ?2, 'opencode', 'historian', NULL, NULL, NULL, ?3, NULL,
                    'completed', 1, 1, 0, 0, NULL, NULL)",
                rusqlite::params![id, "sess-cap", id],
            )
            .expect("insert row");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_subagent_invocations",
                serde_json::json!({ "sessionId": "sess-cap" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json["data"].as_array().map(Vec::len),
            Some(SUBAGENT_INVOCATIONS_LIMIT_MAX)
        );
    }

    #[test]
    fn dreamer_routes_are_allowlisted_as_sensitive_reads_only() {
        assert_eq!(
            find_command_spec("get_dream_queue").map(|spec| spec.access),
            Some(CommandAccess::SensitiveRead)
        );
        assert_eq!(
            find_command_spec("get_dream_state").map(|spec| spec.access),
            Some(CommandAccess::SensitiveRead)
        );
        assert_eq!(
            find_command_spec("get_dream_runs").map(|spec| spec.access),
            Some(CommandAccess::SensitiveRead)
        );
        assert_eq!(
            find_command_spec("get_dream_run_memory_changes").map(|spec| spec.access),
            Some(CommandAccess::SensitiveRead)
        );
        assert!(find_command_spec("enqueue_dream").is_none());
        assert!(find_command_spec("delete_dream_queue_entry").is_none());
    }

    #[tokio::test]
    async fn dream_queue_rejects_without_token_and_allows_valid_token() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);

        let app = build_router(test_state(Some(db_path), 1422));
        let forbidden = app
            .clone()
            .oneshot(valid_request("/api/get_dream_queue"))
            .await
            .expect("response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .oneshot(valid_request_with_token(
                "/api/get_dream_queue",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn enqueue_dream_route_returns_404_even_with_valid_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/enqueue_dream",
                serde_json::json!({ "projectPath": "/tmp/project", "reason": "test" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_dream_queue_entry_route_returns_404_even_with_valid_token() {
        let app = build_router(test_state(None, 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/delete_dream_queue_entry",
                serde_json::json!({ "id": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dream_queue_missing_origin_requires_token() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);

        let app = build_router(test_state(Some(db_path), 1422));
        let forbidden = app
            .clone()
            .oneshot(valid_request_without_origin("/api/get_dream_queue", None))
            .await
            .expect("response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .oneshot(valid_request_without_origin(
                "/api/get_dream_queue",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dream_queue_and_state_accept_empty_or_default_body() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);
        conn.execute(
            "INSERT INTO dream_state (key, value) VALUES (?1, ?2)",
            rusqlite::params!["last_dream_at", "123"],
        )
        .expect("insert dream_state");

        let app = build_router(test_state(Some(db_path), 1422));
        let queue_response = app
            .clone()
            .oneshot(valid_empty_body_request(
                "/api/get_dream_queue",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");
        assert_eq!(queue_response.status(), StatusCode::OK);

        let state_response = app
            .oneshot(valid_json_request(
                "/api/get_dream_state",
                serde_json::json!({}),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(state_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dream_runs_accept_project_path_aliases() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);
        insert_dream_run(&conn, 1, "/tmp/project-a", 1000, 2000);
        insert_dream_run(&conn, 2, "/tmp/project-b", 3000, 4000);

        let app = build_router(test_state(Some(db_path), 1422));
        let camel_response = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_dream_runs",
                serde_json::json!({ "projectPath": "/tmp/project-a", "limit": 10 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(camel_response.status(), StatusCode::OK);
        let camel_json = response_json(camel_response).await;
        assert_eq!(camel_json["data"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            camel_json["data"][0]["project_path"],
            Value::String("/tmp/project-a".into())
        );

        let snake_response = app
            .oneshot(valid_json_request(
                "/api/get_dream_runs",
                serde_json::json!({ "project_path": "/tmp/project-b", "limit": 10 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(snake_response.status(), StatusCode::OK);
        let snake_json = response_json(snake_response).await;
        assert_eq!(snake_json["data"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            snake_json["data"][0]["project_path"],
            Value::String("/tmp/project-b".into())
        );
    }

    #[tokio::test]
    async fn dream_run_memory_changes_accepts_run_id_and_rejects_missing_or_malformed() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);
        insert_dream_run(&conn, 1, "/tmp/project-a", 1000, 2000);
        conn.execute(
            "INSERT INTO memories (id, project_path, category, content, status, created_at, updated_at, superseded_by_memory_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![1_i64, "/tmp/project-a", "fact", "written", "active", 1500_i64, 1500_i64, Option::<i64>::None],
        )
        .expect("insert memory");

        let app = build_router(test_state(Some(db_path), 1422));
        let ok_response = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_dream_run_memory_changes",
                serde_json::json!({ "runId": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(ok_response.status(), StatusCode::OK);

        let missing_response = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_dream_run_memory_changes",
                serde_json::json!({}),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(missing_response.status(), StatusCode::BAD_REQUEST);

        let malformed_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/get_dream_run_memory_changes")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::ORIGIN, "http://127.0.0.1:1420")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(LOCAL_AUTH_TOKEN_HEADER, TEST_LOCAL_AUTH_TOKEN)
                    .body(Body::from("{"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(malformed_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dream_queue_endpoint_is_bounded_to_fifty_rows() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);
        for i in 0..60_i64 {
            conn.execute(
                "INSERT INTO dream_queue (id, project_path, reason, enqueued_at, started_at, retry_count)
                 VALUES (?1, ?2, ?3, ?4, NULL, 0)",
                rusqlite::params![i + 1, format!("/tmp/project-{i}"), format!("reason-{i}"), 1000_i64 + i],
            )
            .expect("insert dream_queue row");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_request_with_token(
                "/api/get_dream_queue",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["data"].as_array().map(Vec::len), Some(50));
    }

    #[tokio::test]
    async fn dream_state_endpoint_is_bounded_to_two_hundred_rows() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);
        for i in 0..205_i64 {
            conn.execute(
                "INSERT INTO dream_state (key, value) VALUES (?1, ?2)",
                rusqlite::params![format!("key-{i:03}"), format!("value-{i:03}")],
            )
            .expect("insert dream_state row");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_request_with_token(
                "/api/get_dream_state",
                Some(TEST_LOCAL_AUTH_TOKEN),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(
            json["data"].as_array().map(Vec::len),
            Some(DREAM_STATE_LIMIT_MAX)
        );
    }

    #[tokio::test]
    async fn dream_runs_limit_is_clamped_to_max() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);
        for i in 0..60_i64 {
            insert_dream_run(&conn, i + 1, "/tmp/project-a", 1000_i64 + i, 2000_i64 + i);
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_dream_runs",
                serde_json::json!({ "projectPath": "/tmp/project-a", "limit": 999 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(
            json["data"].as_array().map(Vec::len),
            Some(DREAM_RUNS_LIMIT_MAX)
        );

        let min_response = app
            .oneshot(valid_json_request(
                "/api/get_dream_runs",
                serde_json::json!({ "projectPath": "/tmp/project-a", "limit": 0 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(min_response.status(), StatusCode::OK);
        let min_json = response_json(min_response).await;
        assert_eq!(min_json["data"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn session_viewer_fact_note_routes_have_expected_access_classes() {
        assert_eq!(
            find_command_spec("get_smart_notes").map(|spec| spec.access),
            Some(CommandAccess::SensitiveRead)
        );
        assert_eq!(
            find_command_spec("update_session_fact").map(|spec| spec.access),
            Some(CommandAccess::Write)
        );
        assert_eq!(
            find_command_spec("update_note").map(|spec| spec.access),
            Some(CommandAccess::Write)
        );
        assert_eq!(
            find_command_spec("dismiss_note").map(|spec| spec.access),
            Some(CommandAccess::Write)
        );
        assert_eq!(
            find_command_spec("delete_session_fact").map(|spec| spec.access),
            Some(CommandAccess::SideEffect)
        );
        assert_eq!(
            find_command_spec("delete_note").map(|spec| spec.access),
            Some(CommandAccess::SideEffect)
        );
        assert!(find_command_spec("get_session_facts").is_none());
        assert!(find_command_spec("get_session_notes").is_none());
    }

    #[tokio::test]
    async fn get_smart_notes_excludes_dismissed_notes_within_result_window() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        for i in 0..5_i64 {
            conn.execute(
                "INSERT INTO notes (
                    id, type, status, content, session_id, project_path, surface_condition,
                    created_at, updated_at, last_checked_at, ready_at, ready_reason
                ) VALUES (?1, 'smart', 'active', ?2, NULL, ?3, ?4, ?5, ?5, NULL, NULL, NULL)",
                rusqlite::params![
                    i + 1,
                    format!("smart-{i}"),
                    "/tmp/project-a",
                    format!("when-{i}"),
                    1000_i64 + i
                ],
            )
            .expect("insert smart note");
        }
        conn.execute(
            "INSERT INTO notes (
                id, type, status, content, session_id, project_path, surface_condition,
                    created_at, updated_at, last_checked_at, ready_at, ready_reason
            ) VALUES (?1, 'smart', 'dismissed', 'gone', NULL, ?2, 'later', ?3, ?3, NULL, NULL, NULL)",
            rusqlite::params![999_i64, "/tmp/project-a", 1002_i64],
        )
        .expect("insert dismissed smart note");

        let app = build_router(test_state(Some(db_path), 1422));
        let forbidden = app
            .clone()
            .oneshot(valid_json_request(
                "/api/get_smart_notes",
                serde_json::json!({ "projectPath": "/tmp/project-a" }),
                None,
                false,
            ))
            .await
            .expect("response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(valid_json_request(
                "/api/get_smart_notes",
                serde_json::json!({ "project_path": "/tmp/project-a" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        let notes = json["data"].as_array().expect("notes array");
        assert_eq!(notes.len(), 5);
        assert!(notes
            .iter()
            .all(|note| note["status"] != Value::String("dismissed".into())));
        assert_eq!(
            notes.first().and_then(|note| note["content"].as_str()),
            Some("smart-0")
        );
    }

    #[tokio::test]
    async fn get_smart_notes_caps_results_to_two_hundred_rows() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        for i in 0..205_i64 {
            conn.execute(
                "INSERT INTO notes (
                    id, type, status, content, session_id, project_path, surface_condition,
                    created_at, updated_at, last_checked_at, ready_at, ready_reason
                ) VALUES (?1, 'smart', 'active', ?2, NULL, ?3, ?4, ?5, ?5, NULL, NULL, NULL)",
                rusqlite::params![
                    i + 1,
                    format!("smart-{i}"),
                    "/tmp/project-a",
                    format!("when-{i}"),
                    1000_i64 + i
                ],
            )
            .expect("insert smart note");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_smart_notes",
                serde_json::json!({ "project_path": "/tmp/project-a" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        let notes = json["data"].as_array().expect("notes array");
        assert_eq!(notes.len(), SMART_NOTES_LIMIT_MAX);
        assert_eq!(
            notes.first().and_then(|note| note["content"].as_str()),
            Some("smart-0")
        );
        assert_eq!(
            notes.last().and_then(|note| note["content"].as_str()),
            Some("smart-199")
        );
    }

    #[tokio::test]
    async fn update_session_fact_mutates_content_and_bumps_version() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_session_fact_row(&conn, 1, "sess-1", "before", 1000);

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/update_session_fact",
                serde_json::json!({ "factId": 1, "content": "after" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let content: String = verify
            .query_row(
                "SELECT content FROM session_facts WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("fact content");
        assert_eq!(content, "after");
        let version: i64 = verify
            .query_row(
                "SELECT session_facts_version FROM session_meta WHERE session_id = 'sess-1'",
                [],
                |row| row.get(0),
            )
            .expect("fact version");
        assert_eq!(version, 1);
    }

    #[tokio::test]
    async fn update_session_fact_rejects_invalid_ids_before_db_mutation() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_session_fact_row(&conn, 1, "sess-1", "before", 1000);

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        for payload in [
            serde_json::json!({ "factId": 0, "content": "after" }),
            serde_json::json!({ "factId": -1, "content": "after" }),
            serde_json::json!({ "content": "after" }),
        ] {
            let response = app
                .clone()
                .oneshot(valid_json_request(
                    "/api/update_session_fact",
                    payload,
                    Some(TEST_LOCAL_AUTH_TOKEN),
                    false,
                ))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let content: String = verify
            .query_row(
                "SELECT content FROM session_facts WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("fact content");
        assert_eq!(content, "before");
        let version: i64 = verify
            .query_row(
                "SELECT session_facts_version FROM session_meta WHERE session_id = 'sess-1'",
                [],
                |row| row.get(0),
            )
            .expect("fact version");
        assert_eq!(version, 0);
    }

    #[tokio::test]
    async fn delete_session_fact_deletes_row_and_bumps_version() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_session_fact_row(&conn, 1, "sess-1", "before", 1000);

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/delete_session_fact",
                serde_json::json!({ "factId": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let count: i64 = verify
            .query_row(
                "SELECT COUNT(*) FROM session_facts WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("fact count");
        assert_eq!(count, 0);
        let version: i64 = verify
            .query_row(
                "SELECT session_facts_version FROM session_meta WHERE session_id = 'sess-1'",
                [],
                |row| row.get(0),
            )
            .expect("fact version");
        assert_eq!(version, 1);
    }

    #[tokio::test]
    async fn delete_session_fact_missing_token_does_not_delete() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_session_fact_row(&conn, 1, "sess-1", "before", 1000);

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/delete_session_fact",
                serde_json::json!({ "factId": 1 }),
                None,
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let count: i64 = verify
            .query_row(
                "SELECT COUNT(*) FROM session_facts WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("fact count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn update_note_mutates_content_and_updated_at() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_note_row(
            &conn,
            1,
            "session",
            "active",
            "before",
            Some("sess-1"),
            None,
            1000,
            None,
        );

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/update_note",
                serde_json::json!({ "noteId": 1, "content": "after" }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let (content, updated_at): (String, i64) = verify
            .query_row(
                "SELECT content, updated_at FROM notes WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("note row");
        assert_eq!(content, "after");
        assert!(updated_at >= 1000);
    }

    #[tokio::test]
    async fn update_note_rejects_oversized_content_without_mutation() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_note_row(
            &conn,
            1,
            "session",
            "active",
            "before",
            Some("sess-1"),
            None,
            1000,
            None,
        );

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let oversized = "x".repeat(services::SESSION_VIEWER_CONTENT_MAX_BYTES + 1);
        let response = app
            .oneshot(valid_json_request(
                "/api/update_note",
                serde_json::json!({ "noteId": 1, "content": oversized }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let (content, updated_at): (String, i64) = verify
            .query_row(
                "SELECT content, updated_at FROM notes WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("note row");
        assert_eq!(content, "before");
        assert_eq!(updated_at, 1000);
    }

    #[tokio::test]
    async fn dismiss_note_sets_status_and_missing_token_does_not_mutate() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_note_row(
            &conn,
            1,
            "session",
            "active",
            "before",
            Some("sess-1"),
            None,
            1000,
            None,
        );

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let forbidden = app
            .clone()
            .oneshot(valid_json_request(
                "/api/dismiss_note",
                serde_json::json!({ "noteId": 1 }),
                None,
                false,
            ))
            .await
            .expect("response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let initial = rusqlite::Connection::open(&db_path).expect("verify db");
        let status: String = initial
            .query_row("SELECT status FROM notes WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("note status");
        assert_eq!(status, "active");

        let allowed = app
            .oneshot(valid_json_request(
                "/api/dismiss_note",
                serde_json::json!({ "note_id": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::OK);

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let status: String = verify
            .query_row("SELECT status FROM notes WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("note status");
        assert_eq!(status, "dismissed");
    }

    #[tokio::test]
    async fn delete_note_removes_row_and_missing_token_does_not_delete() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_session_viewer_tables(&conn);
        insert_note_row(
            &conn,
            1,
            "session",
            "active",
            "before",
            Some("sess-1"),
            None,
            1000,
            None,
        );

        let app = build_router(test_state(Some(db_path.clone()), 1422));
        let forbidden = app
            .clone()
            .oneshot(valid_json_request(
                "/api/delete_note",
                serde_json::json!({ "noteId": 1 }),
                None,
                false,
            ))
            .await
            .expect("response");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let still_there = rusqlite::Connection::open(&db_path).expect("verify db");
        let count: i64 = still_there
            .query_row("SELECT COUNT(*) FROM notes WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("note count");
        assert_eq!(count, 1);

        let allowed = app
            .oneshot(valid_json_request(
                "/api/delete_note",
                serde_json::json!({ "note_id": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::OK);

        let verify = rusqlite::Connection::open(&db_path).expect("verify db");
        let count: i64 = verify
            .query_row("SELECT COUNT(*) FROM notes WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("note count");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn malformed_or_missing_required_fields_return_structured_bad_request() {
        let app = build_router(test_state(None, 1422));

        let missing_field = app
            .clone()
            .oneshot(valid_json_request(
                "/api/delete_note",
                serde_json::json!({}),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(missing_field.status(), StatusCode::BAD_REQUEST);
        let missing_json = response_json(missing_field).await;
        assert_eq!(missing_json["ok"], Value::Bool(false));
        assert!(missing_json["error"].as_str().is_some());

        let malformed = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/update_note")
                    .header(header::HOST, "127.0.0.1:1422")
                    .header(header::ORIGIN, "http://127.0.0.1:1420")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(LOCAL_AUTH_TOKEN_HEADER, TEST_LOCAL_AUTH_TOKEN)
                    .body(Body::from("{"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let malformed_json = response_json(malformed).await;
        assert_eq!(malformed_json["ok"], Value::Bool(false));
        assert!(malformed_json["error"].as_str().is_some());
    }

    #[tokio::test]
    async fn dream_run_memory_changes_are_db_capped_and_report_truncation() {
        let temp_dir = tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("context.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create db");
        create_dreamer_tables(&conn);
        insert_dream_run(&conn, 1, "/tmp/project-a", 1000, 2000);
        for i in 0..205_i64 {
            conn.execute(
                "INSERT INTO memories (id, project_path, category, content, status, created_at, updated_at, superseded_by_memory_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    i + 1,
                    "/tmp/project-a",
                    "fact",
                    format!("memory-{i:03}"),
                    "active",
                    1100_i64 + i,
                    1100_i64 + i,
                    Option::<i64>::None
                ],
            )
            .expect("insert memory row");
        }

        let app = build_router(test_state(Some(db_path), 1422));
        let response = app
            .oneshot(valid_json_request(
                "/api/get_dream_run_memory_changes",
                serde_json::json!({ "runId": 1 }),
                Some(TEST_LOCAL_AUTH_TOKEN),
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        let data = &json["data"];
        let total = data["written"].as_array().map(Vec::len).unwrap_or(0)
            + data["archived"].as_array().map(Vec::len).unwrap_or(0)
            + data["merged"].as_array().map(Vec::len).unwrap_or(0);
        assert_eq!(total, DREAM_MEMORY_CHANGES_LIMIT_MAX);
        assert_eq!(data["truncated"], Value::Bool(true));
        assert_eq!(
            data["limit"],
            Value::from(DREAM_MEMORY_CHANGES_LIMIT_MAX as u64)
        );
    }

    #[test]
    fn positive_limit_clamp_enforces_default_min_and_max() {
        assert_eq!(clamp_positive_limit(None, 20, DREAM_RUNS_LIMIT_MAX), 20);
        assert_eq!(clamp_positive_limit(Some(0), 20, DREAM_RUNS_LIMIT_MAX), 1);
        assert_eq!(clamp_positive_limit(Some(-5), 20, DREAM_RUNS_LIMIT_MAX), 1);
        assert_eq!(
            clamp_positive_limit(Some(999), 20, DREAM_RUNS_LIMIT_MAX),
            DREAM_RUNS_LIMIT_MAX
        );
    }

    async fn response_json(response: Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("json")
    }

    fn create_dreamer_tables(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE dream_queue (
                id INTEGER PRIMARY KEY,
                project_path TEXT NOT NULL,
                reason TEXT NOT NULL,
                enqueued_at INTEGER NOT NULL,
                started_at INTEGER,
                retry_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE dream_state (
                key TEXT NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE dream_runs (
                id INTEGER PRIMARY KEY,
                project_path TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER NOT NULL,
                holder_id TEXT,
                tasks_json TEXT NOT NULL,
                tasks_succeeded INTEGER NOT NULL,
                tasks_failed INTEGER NOT NULL,
                smart_notes_surfaced INTEGER NOT NULL,
                smart_notes_pending INTEGER NOT NULL,
                memory_changes_json TEXT
            );
            CREATE TABLE memories (
                id INTEGER PRIMARY KEY,
                project_path TEXT NOT NULL,
                category TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                superseded_by_memory_id INTEGER
            );",
        )
        .expect("create dreamer schema");
    }

    fn create_session_viewer_tables(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE session_facts (
                id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE session_meta (
                session_id TEXT PRIMARY KEY,
                session_facts_version INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE notes (
                id INTEGER PRIMARY KEY,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                content TEXT NOT NULL,
                session_id TEXT,
                project_path TEXT,
                surface_condition TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_checked_at INTEGER,
                ready_at INTEGER,
                ready_reason TEXT
            );",
        )
        .expect("create session viewer schema");
    }

    fn insert_session_fact_row(
        conn: &rusqlite::Connection,
        id: i64,
        session_id: &str,
        content: &str,
        ts: i64,
    ) {
        conn.execute(
            "INSERT OR IGNORE INTO session_meta (session_id, session_facts_version) VALUES (?1, 0)",
            rusqlite::params![session_id],
        )
        .expect("insert session meta");
        conn.execute(
            "INSERT INTO session_facts (id, session_id, content, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            rusqlite::params![id, session_id, content, ts],
        )
        .expect("insert session fact");
    }

    fn insert_note_row(
        conn: &rusqlite::Connection,
        id: i64,
        note_type: &str,
        status: &str,
        content: &str,
        session_id: Option<&str>,
        project_path: Option<&str>,
        ts: i64,
        surface_condition: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO notes (
                id, type, status, content, session_id, project_path, surface_condition,
                created_at, updated_at, last_checked_at, ready_at, ready_reason
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, NULL, NULL, NULL)",
            rusqlite::params![
                id,
                note_type,
                status,
                content,
                session_id,
                project_path,
                surface_condition,
                ts
            ],
        )
        .expect("insert note");
    }

    fn insert_dream_run(
        conn: &rusqlite::Connection,
        id: i64,
        project_path: &str,
        started_at: i64,
        finished_at: i64,
    ) {
        conn.execute(
            "INSERT INTO dream_runs (
                id, project_path, started_at, finished_at, holder_id, tasks_json,
                tasks_succeeded, tasks_failed, smart_notes_surfaced, smart_notes_pending,
                memory_changes_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                id,
                project_path,
                started_at,
                finished_at,
                "holder-1",
                "[]",
                1_i64,
                0_i64,
                0_i64,
                0_i64,
                Option::<String>::None
            ],
        )
        .expect("insert dream run");
    }

    fn test_state(db_path: Option<PathBuf>, server_port: u16) -> WebServerState {
        test_state_with_dist(db_path, server_port, None)
    }

    fn test_state_with_dist(
        db_path: Option<PathBuf>,
        server_port: u16,
        dist_dir: Option<PathBuf>,
    ) -> WebServerState {
        let app_state = Arc::new(AppState::new());
        *app_state.db_path.lock().expect("db_path lock") = db_path;

        let static_assets = match dist_dir {
            Some(dist_dir) => StaticAssets::from_candidate(dist_dir, "test".into()),
            None => StaticAssets {
                dist_dir: None,
                index_file: None,
                missing_message: Arc::new(
                    "dashboard build output not found. Run `bun run build` in packages/dashboard."
                        .into(),
                ),
            },
        };

        WebServerState {
            app_state,
            server_port,
            static_assets,
            local_auth_token: TEST_LOCAL_AUTH_TOKEN.to_string(),
        }
    }

    fn valid_request(uri: &str) -> Request<Body> {
        valid_request_with_token(uri, None)
    }

    fn valid_request_with_token(uri: &str, token: Option<&str>) -> Request<Body> {
        valid_json_request(uri, serde_json::json!({}), token, false)
    }

    fn valid_empty_body_request(uri: &str, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, "127.0.0.1:1422")
            .header(header::ORIGIN, "http://127.0.0.1:1420")
            .header(header::CONTENT_TYPE, "application/json");

        if let Some(token) = token {
            builder = builder.header(LOCAL_AUTH_TOKEN_HEADER, token);
        }

        builder.body(Body::empty()).expect("request")
    }

    fn valid_json_request(
        uri: &str,
        payload: Value,
        token: Option<&str>,
        include_legacy_local_header: bool,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, "127.0.0.1:1422")
            .header(header::ORIGIN, "http://127.0.0.1:1420")
            .header(header::CONTENT_TYPE, "application/json");

        if let Some(token) = token {
            builder = builder.header(LOCAL_AUTH_TOKEN_HEADER, token);
        }

        if include_legacy_local_header {
            builder = builder.header("X-Magic-Context-Local", "1");
        }

        builder
            .body(Body::from(payload.to_string()))
            .expect("request")
    }

    fn valid_raw_json_request(uri: &str, body: &str, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, "127.0.0.1:1422")
            .header(header::ORIGIN, "http://127.0.0.1:1420")
            .header(header::CONTENT_TYPE, "application/json");

        if let Some(token) = token {
            builder = builder.header(LOCAL_AUTH_TOKEN_HEADER, token);
        }

        builder.body(Body::from(body.to_string())).expect("request")
    }

    fn valid_request_without_origin(uri: &str, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, "127.0.0.1:1422")
            .header(header::CONTENT_TYPE, "application/json");

        if let Some(token) = token {
            builder = builder.header(LOCAL_AUTH_TOKEN_HEADER, token);
        }

        builder.body(Body::from("{}")).expect("request")
    }

    async fn spawn_test_server(app: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, handle)
    }

    async fn read_ok_json(response: Response) -> Value {
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("json")
    }

    async fn read_error_json(response: Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("json")
    }

    fn missing_candidate_path(name: &str) -> String {
        format!("/definitely-missing-{name}-candidate")
    }

    fn create_python_executable(path: PathBuf, body: &str) -> PathBuf {
        let mut file = fs::File::create(&path).expect("create script");
        writeln!(file, "#!/usr/bin/env python3").expect("write shebang");
        file.write_all(body.as_bytes()).expect("write script body");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path).expect("script metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("script permissions");
        }

        path
    }

    fn wait_for_pid_exit(pid: u32) {
        let proc_path = PathBuf::from(format!("/proc/{pid}"));
        for _ in 0..50 {
            if !proc_path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("pid {pid} still alive after timeout");
    }

    struct ConfigTestFixture {
        temp: tempfile::TempDir,
        user_config_path: PathBuf,
        pi_config_path: PathBuf,
        root_project_dir: PathBuf,
        root_config_path: PathBuf,
        alt_project_dir: PathBuf,
        alt_config_path: PathBuf,
        no_config_project_dir: PathBuf,
        unknown_project_dir: PathBuf,
        symlink_project_dir: PathBuf,
        old_xdg_config_home: Option<std::ffi::OsString>,
        old_xdg_data_home: Option<std::ffi::OsString>,
        old_pi_home: Option<std::ffi::OsString>,
    }

    impl ConfigTestFixture {
        fn new() -> Self {
            let temp = tempdir().expect("temp dir");
            let config_home = temp.path().join("config-home");
            let data_home = temp.path().join("data-home");
            let pi_home = temp.path().join("pi-home");
            fs::create_dir_all(&config_home).expect("config home");
            fs::create_dir_all(&data_home).expect("data home");
            fs::create_dir_all(&pi_home).expect("pi home");

            let root_project_dir = temp.path().join("root-project");
            fs::create_dir_all(&root_project_dir).expect("root project");
            let root_config_path = root_project_dir.join("magic-context.jsonc");
            fs::write(&root_config_path, "{\n  \"root\": true\n}").expect("root config");

            let alt_project_dir = temp.path().join("alt-project");
            fs::create_dir_all(alt_project_dir.join(".opencode")).expect("alt project");
            let alt_config_path = alt_project_dir
                .join(".opencode")
                .join("magic-context.jsonc");
            fs::write(&alt_config_path, "{\n  \"alt\": true\n}").expect("alt config");

            let no_config_project_dir = temp.path().join("no-config-project");
            fs::create_dir_all(&no_config_project_dir).expect("no config project");

            let unknown_project_dir = temp.path().join("unknown-project");
            fs::create_dir_all(&unknown_project_dir).expect("unknown project");

            let symlink_project_dir = temp.path().join("symlink-project");
            fs::create_dir_all(&symlink_project_dir).expect("symlink project");
            let outside_dir = temp.path().join("outside-config");
            fs::create_dir_all(&outside_dir).expect("outside dir");
            fs::write(
                outside_dir.join("magic-context.jsonc"),
                "{\n  \"escape\": true\n}",
            )
            .expect("outside config");
            #[cfg(unix)]
            std::os::unix::fs::symlink(&outside_dir, symlink_project_dir.join(".opencode"))
                .expect("symlink .opencode");

            let opencode_dir = data_home.join("opencode");
            fs::create_dir_all(&opencode_dir).expect("opencode dir");
            let opencode_db_path = opencode_dir.join("opencode.db");
            let conn = rusqlite::Connection::open(&opencode_db_path).expect("opencode db");
            conn.execute("CREATE TABLE project (name TEXT, worktree TEXT)", [])
                .expect("create project table");
            for (name, worktree) in [
                ("zeta", root_project_dir.to_string_lossy().to_string()),
                ("Alpha", alt_project_dir.to_string_lossy().to_string()),
                ("beta", no_config_project_dir.to_string_lossy().to_string()),
                ("Gamma", symlink_project_dir.to_string_lossy().to_string()),
            ] {
                conn.execute(
                    "INSERT INTO project (name, worktree) VALUES (?1, ?2)",
                    rusqlite::params![name, worktree],
                )
                .expect("insert project row");
            }

            Self {
                temp,
                user_config_path: config_home.join("opencode").join("magic-context.jsonc"),
                pi_config_path: pi_home
                    .join(".pi")
                    .join("agent")
                    .join("magic-context.jsonc"),
                root_project_dir,
                root_config_path,
                alt_project_dir,
                alt_config_path,
                no_config_project_dir,
                unknown_project_dir,
                symlink_project_dir,
                old_xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
                old_xdg_data_home: std::env::var_os("XDG_DATA_HOME"),
                old_pi_home: std::env::var_os("MAGIC_CONTEXT_DASHBOARD_TEST_HOME"),
            }
        }

        fn set_env(&self) {
            std::env::set_var(
                "XDG_CONFIG_HOME",
                self.user_config_path
                    .parent()
                    .and_then(|p| p.parent())
                    .expect("config home root"),
            );
            std::env::set_var("XDG_DATA_HOME", self.temp.path().join("data-home"));
            std::env::set_var(
                "MAGIC_CONTEXT_DASHBOARD_TEST_HOME",
                self.temp.path().join("pi-home"),
            );
        }
    }

    impl Drop for ConfigTestFixture {
        fn drop(&mut self) {
            restore_env_var("XDG_CONFIG_HOME", self.old_xdg_config_home.take());
            restore_env_var("XDG_DATA_HOME", self.old_xdg_data_home.take());
            restore_env_var("MAGIC_CONTEXT_DASHBOARD_TEST_HOME", self.old_pi_home.take());
        }
    }

    fn restore_env_var(name: &str, value: Option<std::ffi::OsString>) {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    fn create_user_memory_test_db(db_path: &PathBuf, memory_count: usize, candidate_count: usize) {
        let conn = rusqlite::Connection::open(db_path).expect("create db");
        conn.execute_batch(
            "CREATE TABLE project_state (
                project_path TEXT PRIMARY KEY,
                project_memory_epoch INTEGER NOT NULL,
                project_user_profile_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE user_memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                status TEXT NOT NULL,
                promoted_at INTEGER,
                source_candidate_ids TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE user_memory_candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source_compartment_start INTEGER,
                source_compartment_end INTEGER,
                created_at INTEGER NOT NULL
            );",
        )
        .expect("create user memory schema");
        conn.execute(
            "INSERT INTO project_state (project_path, project_memory_epoch, project_user_profile_version, updated_at)
             VALUES ('__global__', 0, 0, 0)",
            [],
        )
        .expect("seed global project state");

        for i in 0..memory_count {
            let status = if i % 2 == 0 { "active" } else { "dismissed" };
            conn.execute(
                "INSERT INTO user_memories (content, status, promoted_at, source_candidate_ids, created_at, updated_at)
                 VALUES (?1, ?2, NULL, '[]', ?3, ?3)",
                rusqlite::params![format!("memory {}", i + 1), status, (i + 1) as i64],
            )
            .expect("insert user memory");
        }

        for i in 0..candidate_count {
            conn.execute(
                "INSERT INTO user_memory_candidates (content, session_id, source_compartment_start, source_compartment_end, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    format!("candidate {}", i + 1),
                    format!("session-{}", i + 1),
                    (i as i64) + 1,
                    (i as i64) + 2,
                    (i + 1) as i64,
                ],
            )
            .expect("insert candidate");
        }
    }

    fn user_profile_version_from_db(conn: &rusqlite::Connection) -> i64 {
        conn.query_row(
            "SELECT project_user_profile_version FROM project_state WHERE project_path = '__global__'",
            [],
            |row| row.get(0),
        )
        .expect("user profile version")
    }

    fn write_pi_session_fixture(
        dir: &tempfile::TempDir,
        session_id: &str,
        message_count: usize,
    ) -> Result<PathBuf, std::io::Error> {
        let session_dir = dir.path().join("--tmp-proj--");
        fs::create_dir_all(&session_dir)?;
        let path = session_dir.join(format!("{session_id}.jsonl"));
        let mut file = fs::File::create(&path)?;
        writeln!(
            file,
            "{{\"type\":\"session\",\"version\":3,\"id\":\"{session_id}\",\"timestamp\":\"2026-01-01T00:00:00.000Z\",\"cwd\":\"/tmp/proj\"}}"
        )?;
        for i in 0..message_count {
            let parent = if i == 0 {
                "null".to_string()
            } else {
                format!("\"m{}\"", i - 1)
            };
            let role = if i % 2 == 0 { "user" } else { "assistant" };
            let usage = if role == "assistant" {
                ",\"usage\":{\"input\":10,\"output\":5,\"cache\":{\"read\":3,\"write\":2},\"total\":20}"
            } else {
                ""
            };
            writeln!(
                file,
                "{{\"type\":\"message\",\"id\":\"m{i}\",\"parentId\":{parent},\"timestamp\":\"2026-01-01T00:00:{:02}.000Z\",\"message\":{{\"role\":\"{role}\",\"content\":[{{\"type\":\"text\",\"text\":\"message {i}\"}}]{usage}}}}}",
                i % 60
            )?;
        }
        Ok(path)
    }

    fn valid_get_request(uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("request")
    }
}
