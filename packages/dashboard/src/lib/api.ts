import { callBackend, invokeTauri } from "./backend";
import { isTauriRuntime } from "./runtime";
import type {
  CacheEvent,
  Compartment,
  ConfigFile,
  ContextTokenBreakdown,
  DbCacheEvent,
  DbHealth,
  DreamQueueEntry,
  DreamRun,
  DreamRunMemoryDetail,
  DreamStateEntry,
  Harness,
  KeyFileRow,
  LogEntry,
  Memory,
  MemoryStats,
  Note,
  PagedSessions,
  ProjectRow,
  SessionDetail,
  SessionFact,
  SessionFilter,
  SessionMessageRow,
  SessionMetaRow,
  SessionRow,
  SessionSummary,
  SubagentInvocation,
  SubagentTotals,
  UserMemory,
  UserMemoryCandidate,
  WorkspaceListItem,
  WorkspaceShareCategory,
  WorkspaceSummary,
} from "./types";

// ── Memory API ──────────────────────────────────────────────

export async function getProjects(): Promise<import("./types").ProjectInfo[]> {
  return callBackend("get_projects");
}

export async function getMemories(params?: {
  project?: string;
  workspaceId?: number;
  status?: string;
  category?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<Memory[]> {
  return callBackend("get_memories", {
    project: params?.project ?? null,
    workspaceId: params?.workspaceId ?? null,
    status: params?.status ?? null,
    category: params?.category ?? null,
    search: params?.search ?? null,
    limit: params?.limit ?? 100,
    offset: params?.offset ?? 0,
  });
}

export async function getMemoryStats(params?: {
  project?: string;
  workspaceId?: number;
}): Promise<MemoryStats> {
  return callBackend("get_memory_stats", {
    project: params?.project ?? null,
    workspaceId: params?.workspaceId ?? null,
  });
}

export async function workspaceSchemaReady(): Promise<boolean> {
  return invokeTauri("workspace_schema_ready");
}

export async function listWorkspaces(): Promise<WorkspaceListItem[]> {
  return invokeTauri("list_workspaces");
}

export async function listWorkspaceSummaries(): Promise<WorkspaceSummary[]> {
  return invokeTauri("list_workspace_summaries");
}

export async function createWorkspace(name: string): Promise<number> {
  return invokeTauri("create_workspace", { name });
}

export async function renameWorkspace(workspaceId: number, name: string): Promise<void> {
  return invokeTauri("rename_workspace", { workspaceId, name });
}

export async function deleteWorkspace(workspaceId: number): Promise<void> {
  return invokeTauri("delete_workspace", { workspaceId });
}

export interface WorkspaceMemberChange {
  project_path: string;
  display_name: string;
  display_path: string;
}

export interface WorkspaceDisplayNameChange {
  project_path: string;
  display_name: string;
}

export async function applyWorkspaceChanges(params: {
  workspaceId: number;
  rename: string | null;
  addMembers: WorkspaceMemberChange[];
  removeMembers: string[];
  setDisplayNames: WorkspaceDisplayNameChange[];
  shareCategories: WorkspaceShareCategory[];
}): Promise<void> {
  return invokeTauri("apply_workspace_changes", params);
}

export async function updateMemoryStatus(memoryId: number, status: string): Promise<void> {
  return callBackend("update_memory_status", { memoryId, status });
}

export async function updateMemoryContent(memoryId: number, content: string): Promise<void> {
  return callBackend("update_memory_content", { memoryId, content });
}

export async function updateMemoryCategory(memoryId: number, category: string): Promise<void> {
  return callBackend("update_memory_category", { memoryId, category });
}

export async function deleteMemory(memoryId: number): Promise<void> {
  return callBackend("delete_memory", { memoryId });
}

export async function bulkUpdateMemoryStatus(memoryIds: number[], status: string): Promise<number> {
  return callBackend("bulk_update_memory_status", { memoryIds, status });
}

export async function bulkDeleteMemory(memoryIds: number[]): Promise<number> {
  return callBackend("bulk_delete_memory", { memoryIds });
}

// ── Session API ─────────────────────────────────────────────

export async function getSessions(): Promise<SessionSummary[]> {
  return callBackend("get_sessions");
}

export async function listSessions(filter?: SessionFilter): Promise<SessionRow[]> {
  const sanitized: SessionFilter = {};
  if (filter?.harness) sanitized.harness = filter.harness;
  if (filter?.project_identity) sanitized.project_identity = filter.project_identity;
  if (filter?.search) sanitized.search = filter.search;
  // is_subagent: pass `false` to filter OUT subagents, `true` to keep only
  // subagents. Skip the key entirely when unset so the backend treats it as
  // "no filter" — note `typeof === "boolean"` so we don't drop a literal
  // `false` via truthy check.
  if (typeof filter?.is_subagent === "boolean") sanitized.is_subagent = filter.is_subagent;

  return callBackend("list_sessions", {
    filter: Object.keys(sanitized).length > 0 ? sanitized : null,
  });
}

function sanitizeSessionFilter(filter?: SessionFilter): SessionFilter {
  const sanitized: SessionFilter = {};
  if (filter?.harness) sanitized.harness = filter.harness;
  if (filter?.project_identity) sanitized.project_identity = filter.project_identity;
  if (filter?.search) sanitized.search = filter.search;
  if (typeof filter?.is_subagent === "boolean") sanitized.is_subagent = filter.is_subagent;
  if (typeof filter?.offset === "number") sanitized.offset = filter.offset;
  if (typeof filter?.limit === "number") sanitized.limit = filter.limit;
  return sanitized;
}

export async function listSessionsPaged(filter?: SessionFilter): Promise<PagedSessions> {
  const sanitized = sanitizeSessionFilter(filter);

  return callBackend("list_sessions_paged", {
    filter: Object.keys(sanitized).length > 0 ? sanitized : null,
  });
}

export async function getSessionDetail(
  harness: Harness,
  sessionId: string,
): Promise<SessionDetail> {
  return callBackend("get_session_detail", { harness, sessionId });
}

export async function getSubagentInvocations(sessionId: string): Promise<SubagentInvocation[]> {
  return callBackend("get_subagent_invocations", { sessionId });
}

export async function getSubagentTotalsBySubagent(sessionId: string): Promise<SubagentTotals[]> {
  return callBackend("get_subagent_totals_by_subagent", { sessionId });
}

export async function getSessionCacheEvents(
  harness: Harness,
  sessionId: string,
  // Caps the returned event count to the most recent N. Pass undefined or omit
  // for the whole session — but be aware that a hot OpenCode session can emit
  // 30k+ events (≈8MB of JSON across the Tauri IPC boundary), so chart-bound
  // callers should always pass a small bound. The dashboard's Cache page uses
  // the window picker (200–1000) for the initial/full load.
  limit?: number,
  // Incremental mode: when set, return this session's events with
  // `time_created >= sinceTimestamp` in chronological order (the `>=` overlaps
  // the caller's last-seen event by one row so cross-step severity is computed
  // correctly; dedupe by message_id). `limit` is ignored when this is set.
  sinceTimestamp?: number | null,
): Promise<DbCacheEvent[]> {
  return callBackend("get_session_cache_events", {
    harness,
    sessionId,
    ...(isTauriRuntime()
      ? typeof limit === "number"
        ? { limit }
        : {}
      : { limit: limit ?? 600 }),
    sinceTimestamp: sinceTimestamp ?? null,
  });
}

/**
 * Fetch cache events for a session, trimmed to at most `targetTurns` complete
 * turns (most recent first). Use this for the Cache Hit Timeline so multi-step
 * tool-use turns don't collapse the bar chart.
 */
export async function getSessionCacheEventsByTurns(
  harness: Harness,
  sessionId: string,
  targetTurns: number,
): Promise<DbCacheEvent[]> {
  return callBackend("get_session_cache_events_by_turns", {
    harness,
    sessionId,
    targetTurns,
  });
}

/**
 * Lazy fetch for the Messages tab. Returns the full message list for a session
 * (37k+ rows for long OpenCode sessions, ~28MB IPC payload). Only call this
 * when the user activates the Messages tab; `getSessionDetail()` returns a
 * cheap `messages_count` for the tab badge so we never pay this cost up front.
 */
export async function getSessionMessages(
  harness: Harness,
  sessionId: string,
): Promise<SessionMessageRow[]> {
  return callBackend("get_session_messages", { harness, sessionId });
}

export async function getProjectKeyFiles(projectPath: string): Promise<KeyFileRow[]> {
  return callBackend("get_project_key_files", { projectPath });
}

export async function enumerateProjects(): Promise<ProjectRow[]> {
  return invokeTauri("enumerate_projects");
}

export async function enumerateMemoryProjects(): Promise<ProjectRow[]> {
  return invokeTauri("enumerate_memory_projects");
}

export async function getCompartments(sessionId: string): Promise<Compartment[]> {
  return callBackend("get_compartments", { sessionId });
}

export async function getSessionFacts(sessionId: string): Promise<SessionFact[]> {
  return invokeTauri("get_session_facts", { sessionId });
}

export async function getSessionNotes(sessionId: string): Promise<Note[]> {
  return invokeTauri("get_session_notes", { sessionId });
}

export async function getSmartNotes(projectPath: string): Promise<Note[]> {
  return callBackend("get_smart_notes", { projectPath });
}

export async function updateSessionFact(factId: number, content: string): Promise<void> {
  return callBackend("update_session_fact", { factId, content });
}

export async function deleteSessionFact(factId: number): Promise<void> {
  return callBackend("delete_session_fact", { factId });
}

export async function updateNote(noteId: number, content: string): Promise<void> {
  return callBackend("update_note", { noteId, content });
}

export async function deleteNote(noteId: number): Promise<void> {
  return callBackend("delete_note", { noteId });
}

export async function dismissNote(noteId: number): Promise<void> {
  return callBackend("dismiss_note", { noteId });
}

export async function getSessionMeta(sessionId: string): Promise<SessionMetaRow | null> {
  return callBackend("get_session_meta", { sessionId });
}

export async function getContextTokenBreakdown(
  sessionId: string,
): Promise<ContextTokenBreakdown | null> {
  return invokeTauri("get_context_token_breakdown", { sessionId });
}

export async function getSessionCacheStats(
  limit?: number,
): Promise<import("./types").SessionCacheStats[]> {
  return invokeTauri("get_session_cache_stats", { maxLines: 5000, limit: limit ?? 5 });
}

export async function getSessionCacheStatsFromDb(
  limit?: number,
): Promise<import("./types").SessionCacheStats[]> {
  return invokeTauri("get_session_cache_stats_from_db", { limit: limit ?? 5 });
}

// ── Dreamer API ─────────────────────────────────────────────

export async function getDreamQueue(): Promise<DreamQueueEntry[]> {
  return callBackend("get_dream_queue");
}

export async function getDreamState(): Promise<DreamStateEntry[]> {
  return callBackend("get_dream_state");
}

export async function getDreamRuns(projectPath?: string, limit?: number): Promise<DreamRun[]> {
  return callBackend("get_dream_runs", {
    projectPath: projectPath ?? null,
    limit: limit ?? 20,
  });
}

export async function getDreamRunMemoryChanges(runId: number): Promise<DreamRunMemoryDetail> {
  return callBackend("get_dream_run_memory_changes", { runId });
}

export async function enqueueDream(projectPath: string, reason: string): Promise<number> {
  return invokeTauri("enqueue_dream", { projectPath, reason });
}

export async function deleteDreamQueueEntry(id: number): Promise<number> {
  return invokeTauri("delete_dream_queue_entry", { id });
}

// ── Log & Cache API ─────────────────────────────────────────

export async function getLogEntries(maxLines?: number): Promise<LogEntry[]> {
  return callBackend("get_log_entries", { maxLines: maxLines ?? null });
}

export async function getCacheEvents(maxLines?: number): Promise<CacheEvent[]> {
  return invokeTauri("get_cache_events", { maxLines: maxLines ?? 2000 });
}

export async function getCacheEventsFromDb(
  limit?: number,
  sinceTimestamp?: number | null,
): Promise<DbCacheEvent[]> {
  return callBackend("get_cache_events_from_db", {
    limit: limit ?? 200,
    sinceTimestamp: sinceTimestamp ?? null,
  });
}

// ── Config API ──────────────────────────────────────────────

export async function getConfig(source: string): Promise<ConfigFile> {
  return callBackend("get_config", { source });
}

export async function getProjectConfig(projectPath: string): Promise<ConfigFile> {
  return callBackend("get_config", { source: "project", projectPath });
}

export async function saveConfig(source: string, content: string): Promise<void> {
  return callBackend("save_config", { source, content });
}

export async function getPiConfig(): Promise<ConfigFile> {
  return callBackend("read_pi_config");
}

export async function savePiConfig(content: string): Promise<void> {
  return callBackend("write_pi_config", { content });
}

// ── Health API ──────────────────────────────────────────────

export async function getDbHealth(): Promise<DbHealth> {
  return callBackend("get_db_health");
}

export async function getProjectConfigs(): Promise<import("./types").ProjectConfigEntry[]> {
  return callBackend("get_project_configs");
}

export async function saveProjectConfig(projectPath: string, content: string): Promise<void> {
  return callBackend("save_project_config", { projectPath, content });
}

export async function getAvailableModels(): Promise<string[]> {
  return callBackend("get_available_models");
}

export async function getAvailablePiModels(): Promise<string[]> {
  return callBackend("get_available_pi_models");
}

export async function testEmbeddingEndpoint(params: {
  endpoint: string;
  model: string;
  apiKey?: string | null;
  inputType?: string | null;
  truncate?: string | null;
}): Promise<unknown> {
  return callBackend("test_embedding_endpoint", {
    endpoint: params.endpoint,
    model: params.model,
    apiKey: params.apiKey ?? null,
    inputType: params.inputType ?? null,
    truncate: params.truncate ?? null,
  });
}

// ── User Memory API ─────────────────────────────────────────

export async function getUserMemories(status?: string): Promise<UserMemory[]> {
  return callBackend("get_user_memories", {
    status: status ?? null,
    limit: 200,
  });
}

export async function getUserMemoryCandidates(): Promise<UserMemoryCandidate[]> {
  return callBackend("get_user_memory_candidates", { limit: 100 });
}

export async function dismissUserMemory(id: number): Promise<void> {
  return callBackend("dismiss_user_memory", { id });
}

export async function deleteUserMemory(id: number): Promise<void> {
  return callBackend("delete_user_memory", { id });
}

export async function updateUserMemoryContent(id: number, content: string): Promise<void> {
  return callBackend("update_user_memory_content", { id, content });
}

export async function deleteUserMemoryCandidate(id: number): Promise<void> {
  return callBackend("delete_user_memory_candidate", { id });
}

export async function promoteUserMemoryCandidate(id: number): Promise<void> {
  return callBackend("promote_user_memory_candidate", { id });
}

// ── Utilities ───────────────────────────────────────────────

export function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString();
}

export function formatRelativeTime(ts: number): string {
  const now = Date.now();
  const diff = now - ts;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days === 1) return "yesterday";
  if (days > 1) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return `${seconds}s ago`;
}

export function formatDateTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => n.toString().padStart(2, "0");
  const month = d.toLocaleString("en", { month: "short" });
  return `${month} ${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function truncate(str: string, max: number): string {
  if (str.length <= max) return str;
  return `${str.slice(0, max - 1)}…`;
}
