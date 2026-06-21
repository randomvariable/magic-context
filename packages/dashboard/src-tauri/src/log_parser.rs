use regex::Regex;
use serde::Serialize;
use std::path::PathBuf;

pub const LOG_TAIL_READ_CAP_BYTES: u64 = 1024 * 1024;
pub const LOG_ENTRY_MESSAGE_MAX_BYTES: usize = 2 * 1024;

/// Harness identifier — must match the strings used by the TypeScript-side
/// `HarnessId` type (`packages/plugin/src/shared/harness.ts`) and by the
/// per-harness temp-directory layout defined in
/// `packages/plugin/src/shared/data-path.ts:getMagicContextTempDir`.
#[derive(Debug, Clone, Copy)]
pub enum Harness {
    Opencode,
    Pi,
}

impl Harness {
    fn as_str(self) -> &'static str {
        match self {
            Harness::Opencode => "opencode",
            Harness::Pi => "pi",
        }
    }
}

/// Resolve the plugin log file for a specific harness.
///
/// The plugin writes separate logs per harness so a single machine running
/// both can produce two independent issue reports:
///   - OpenCode → `${tmpdir}/opencode/magic-context/magic-context.log`
///   - Pi       → `${tmpdir}/pi/magic-context/magic-context.log`
///
/// Mirrors the resolution done in TypeScript at
/// `packages/plugin/src/shared/data-path.ts:getMagicContextLogPath`. Kept
/// in sync manually because the dashboard doesn't import any TypeScript
/// source.
pub fn resolve_log_path_for(harness: Harness) -> PathBuf {
    std::env::temp_dir()
        .join(harness.as_str())
        .join("magic-context")
        .join("magic-context.log")
}

/// Backwards-compatible default — returns the OpenCode log path. Existing
/// dashboard call sites that don't yet pass a harness keep working against
/// OpenCode, which matches the historical single-harness behavior.
pub fn resolve_log_path() -> PathBuf {
    resolve_log_path_for(Harness::Opencode)
}

#[derive(Debug, Serialize, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub component: String,
    pub session_id: String,
    pub message: String,
    pub raw: Option<String>,
    pub cache_read: Option<i64>,
    pub cache_write: Option<i64>,
    pub hit_ratio: Option<f64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CacheEvent {
    pub timestamp: String,
    pub session_id: String,
    pub cache_read: i64,
    pub cache_write: i64,
    pub input_tokens: i64,
    pub hit_ratio: f64,
    pub cause: Option<String>,
    pub severity: String, // "stable", "warning", "bust", "full_bust"
}

#[derive(Debug, Serialize, Clone)]
pub struct SessionCacheStats {
    pub session_id: String,
    pub event_count: usize,
    pub total_cache_read: i64,
    pub total_cache_write: i64,
    pub total_input: i64,
    pub hit_ratio: f64,
    pub last_timestamp: String,
    pub bust_count: usize,
}

lazy_static::lazy_static! {
    static ref LOG_LINE_RE: Regex = Regex::new(
        r"^\[([^\]]+)\]\s+\[magic-context\]\[([^\]]*)\]\s*(.*)"
    ).unwrap();

    static ref CACHE_STATS_RE: Regex = Regex::new(
        r"cache\.read=(\d+)\s+cache\.write=(\d+)"
    ).unwrap();

    static ref INPUT_TOKENS_RE: Regex = Regex::new(
        r"tokens\.input=(\d+)"
    ).unwrap();

    static ref REDACT_PEM_PRIVATE_KEY_RE: Regex = Regex::new(
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    ).unwrap();
    static ref REDACT_URL_CREDENTIALS_RE: Regex = Regex::new(
        r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"
    ).unwrap();
    static ref REDACT_HOME_PATH_RE: Regex = Regex::new(
        r"(?:/home|/Users)/[^/\s]+"
    ).unwrap();
    static ref REDACT_WINDOWS_HOME_PATH_RE: Regex = Regex::new(
        r"(?i)[A-Z]:\\Users\\[^\\\s]+"
    ).unwrap();
    static ref REDACT_AUTHORIZATION_BEARER_RE: Regex = Regex::new(
        r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"
    ).unwrap();
    static ref REDACT_STANDALONE_BEARER_RE: Regex = Regex::new(
        r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+"
    ).unwrap();
    static ref REDACT_GITHUB_TOKEN_RE: Regex = Regex::new(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]+\b"
    ).unwrap();
    static ref REDACT_GITHUB_PAT_TOKEN_RE: Regex = Regex::new(
        r"\bgithub_pat_[A-Za-z0-9_]+\b"
    ).unwrap();
    static ref REDACT_HF_TOKEN_RE: Regex = Regex::new(
        r"\bhf_[A-Za-z0-9]+\b"
    ).unwrap();
    static ref REDACT_SLACK_TOKEN_RE: Regex = Regex::new(
        r"\b(?:xoxb|xoxa|xoxp|xoxr|xoxs)-[A-Za-z0-9-]+\b"
    ).unwrap();
    static ref REDACT_SLACK_APP_TOKEN_RE: Regex = Regex::new(
        r"\bxapp-[A-Za-z0-9-]+\b"
    ).unwrap();
    static ref REDACT_GOOGLE_API_KEY_RE: Regex = Regex::new(
        r"\bAIza[0-9A-Za-z\-_]{10,}\b"
    ).unwrap();
    static ref REDACT_AWS_ACCESS_KEY_RE: Regex = Regex::new(
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    ).unwrap();
    static ref REDACT_SK_ANT_TOKEN_RE: Regex = Regex::new(
        r"\bsk-ant-[A-Za-z0-9\-_]+\b"
    ).unwrap();
    static ref REDACT_SK_TOKEN_RE: Regex = Regex::new(
        r"\bsk-[A-Za-z0-9\-_]+\b"
    ).unwrap();
    static ref REDACT_JWT_RE: Regex = Regex::new(
        r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    ).unwrap();
    static ref REDACT_SECRET_KV_RE: Regex = Regex::new(
        r#"(?ix)
        (
            "?(?:password|passwd|secret|token|api_key|apikey|apiKey|access_token|refresh_token|client_secret|session_secret|private_key|aws_secret_access_key|secretAccessKey|x-api-key|api-key|anthropic-api-key|openai-api-key)"?
            \s*[:=]\s*
        )
        (
            "[^"]*"
            |'[^']*'
            |[^,\s}\]]+
        )
        "#
    ).unwrap();
}

pub fn parse_log_line(line: &str) -> Option<LogEntry> {
    // Format: [timestamp] [magic-context][session_id] message
    // Also handle: [timestamp] message (no component/session)
    if let Some(caps) = LOG_LINE_RE.captures(line) {
        let timestamp = caps.get(1)?.as_str().to_string();
        let session_id = caps.get(2)?.as_str().to_string();
        let message = caps.get(3)?.as_str().to_string();

        let component = if message.starts_with("event ") {
            "event".to_string()
        } else if message.starts_with("transform") {
            "transform".to_string()
        } else if message.starts_with("[dreamer]") || message.contains("dreamer") {
            "dreamer".to_string()
        } else if message.contains("historian") || message.contains("compartment") {
            "historian".to_string()
        } else if message.contains("nudge") {
            "nudge".to_string()
        } else if message.contains("note-nudge") || message.contains("note nudge") {
            "note-nudge".to_string()
        } else {
            "general".to_string()
        };

        let (cache_read, cache_write, hit_ratio) =
            if let Some(cache_caps) = CACHE_STATS_RE.captures(&message) {
                let read: i64 = cache_caps.get(1)?.as_str().parse().ok()?;
                let write: i64 = cache_caps.get(2)?.as_str().parse().ok()?;
                let total = read + write;
                let ratio = if total > 0 {
                    read as f64 / total as f64
                } else {
                    0.0
                };
                (Some(read), Some(write), Some(ratio))
            } else {
                (None, None, None)
            };

        return Some(LogEntry {
            timestamp,
            component,
            session_id,
            message,
            raw: Some(line.to_string()),
            cache_read,
            cache_write,
            hit_ratio,
        });
    }

    // Fallback: simple timestamp pattern
    if line.starts_with('[') {
        if let Some(end) = line.find(']') {
            let timestamp = line[1..end].to_string();
            let rest = line[end + 1..].trim().to_string();
            return Some(LogEntry {
                timestamp,
                component: "general".to_string(),
                session_id: String::new(),
                message: rest,
                raw: Some(line.to_string()),
                cache_read: None,
                cache_write: None,
                hit_ratio: None,
            });
        }
    }

    None
}

pub fn extract_cache_events(entries: &[LogEntry]) -> Vec<CacheEvent> {
    let mut events = Vec::new();
    let mut last: Option<(&str, i64, i64, i64)> = None;

    for (i, entry) in entries.iter().enumerate() {
        if let (Some(read), Some(write)) = (entry.cache_read, entry.cache_write) {
            let input_tokens = INPUT_TOKENS_RE
                .captures(&entry.message)
                .and_then(|c| c.get(1))
                .and_then(|m| m.as_str().parse::<i64>().ok())
                .unwrap_or(0);

            // Deduplicate consecutive identical events (message.updated fires twice)
            let key = (entry.session_id.as_str(), read, write, input_tokens);
            if last == Some(key) {
                continue;
            }
            last = Some(key);

            // Total prompt tokens = uncached input + cache read + cache write
            let total_prompt = input_tokens + read + write;
            if total_prompt == 0 {
                continue;
            }

            // Real cache hit rate: what fraction of prompt was served from cache
            let ratio = read as f64 / total_prompt as f64;

            // Determine severity and cause based on real hit ratio
            let (severity, cause) = if read == 0 && write > 0 {
                let cause = detect_bust_cause(entries, i);
                // First message and provider eviction are not real busts
                let sev = if cause.starts_with("First message") {
                    "info"
                } else if cause.starts_with("Provider-side") {
                    "warning"
                } else {
                    "full_bust"
                };
                (sev.to_string(), Some(cause))
            } else if ratio < 0.5 {
                let cause = detect_bust_cause(entries, i);
                ("bust".to_string(), Some(cause))
            } else if ratio < 0.9 {
                ("warning".to_string(), None)
            } else {
                ("stable".to_string(), None)
            };

            events.push(CacheEvent {
                timestamp: entry.timestamp.clone(),
                session_id: entry.session_id.clone(),
                cache_read: read,
                cache_write: write,
                input_tokens,
                hit_ratio: ratio,
                cause,
                severity,
            });
        }
    }

    events
}

/// Aggregate cache events into per-session stats, sorted by last activity (most recent first).
pub fn aggregate_session_cache_stats(
    events: &[CacheEvent],
    limit: usize,
) -> Vec<SessionCacheStats> {
    use std::collections::HashMap;

    struct Accum {
        event_count: usize,
        total_read: i64,
        total_write: i64,
        total_input: i64,
        last_timestamp: String,
        bust_count: usize,
    }

    let mut map: HashMap<String, Accum> = HashMap::new();

    for event in events {
        if event.session_id.is_empty() {
            continue;
        }
        let entry = map.entry(event.session_id.clone()).or_insert(Accum {
            event_count: 0,
            total_read: 0,
            total_write: 0,
            total_input: 0,
            last_timestamp: String::new(),
            bust_count: 0,
        });
        entry.event_count += 1;
        entry.total_read += event.cache_read;
        entry.total_write += event.cache_write;
        entry.total_input += event.input_tokens;
        entry.last_timestamp = event.timestamp.clone();
        if event.severity == "bust" || event.severity == "full_bust" {
            entry.bust_count += 1;
        }
    }

    let mut stats: Vec<SessionCacheStats> = map
        .into_iter()
        .map(|(session_id, acc)| {
            let total_prompt = acc.total_read + acc.total_write + acc.total_input;
            let hit_ratio = if total_prompt > 0 {
                acc.total_read as f64 / total_prompt as f64
            } else {
                0.0
            };
            SessionCacheStats {
                session_id,
                event_count: acc.event_count,
                total_cache_read: acc.total_read,
                total_cache_write: acc.total_write,
                total_input: acc.total_input,
                hit_ratio,
                last_timestamp: acc.last_timestamp,
                bust_count: acc.bust_count,
            }
        })
        .collect();

    // Sort by last_timestamp descending (most recent first)
    stats.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));
    stats.truncate(limit);
    stats
}

fn detect_bust_cause(entries: &[LogEntry], event_idx: usize) -> String {
    let event = &entries[event_idx];

    // Look at surrounding log entries for context
    let window_start = event_idx.saturating_sub(10);
    let window_end = std::cmp::min(event_idx + 3, entries.len());

    let mut causes = Vec::new();

    // Check if this is the first cache event for this session
    let is_first_session_event = !entries[..event_idx].iter().any(|e| {
        e.session_id == event.session_id
            && e.cache_read.is_some()
            && (e.cache_read.unwrap_or(0) > 0 || e.cache_write.unwrap_or(0) > 0)
    });

    if is_first_session_event {
        return "First message (new session)".to_string();
    }

    // Check if the transform was a defer pass (no plugin-side mutations)
    let is_defer_pass = entries[window_start..window_end]
        .iter()
        .any(|e| e.session_id == event.session_id && e.message.contains("decision=defer"));

    // If cache.read=0 on a defer pass, it's provider-side eviction
    if is_defer_pass && event.cache_read == Some(0) && event.cache_write.unwrap_or(0) > 0 {
        let has_plugin_mutation = entries[window_start..window_end].iter().any(|e| {
            e.session_id == event.session_id
                && (e.message.contains("Execute pass")
                    || e.message.contains("triggering flush")
                    || e.message.contains("system prompt hash changed")
                    || e.message.contains("variant change"))
        });
        if !has_plugin_mutation {
            return "Provider-side cache eviction".to_string();
        }
    }

    for entry in &entries[window_start..window_end] {
        if entry.session_id != event.session_id {
            continue;
        }
        let msg = &entry.message;
        if msg.contains("Execute pass") || (msg.contains("applied") && msg.contains("ops")) {
            causes.push("Execute pass".to_string());
        }
        if msg.contains("compartments") && msg.contains("→") {
            causes.push("Historian output".to_string());
        }
        if msg.contains("variant change") || msg.contains("Variant change") {
            causes.push("Variant change".to_string());
        }
        if msg.contains("system prompt hash") {
            causes.push("System prompt hash change".to_string());
        }
        if msg.contains("restart")
            || msg.contains("Restart")
            || msg.contains("injection cache cleared")
        {
            causes.push("App restart".to_string());
        }
        if msg.contains("note nudge") && msg.contains("deliver") {
            causes.push("Note nudge delivered".to_string());
        }
        if msg.contains("heuristic cleanup") || msg.contains("tool tags dropped") {
            causes.push("Heuristic cleanup".to_string());
        }
    }

    if causes.is_empty() {
        "Unknown cause".to_string()
    } else {
        causes.dedup();
        causes.join(", ")
    }
}

/// Read the last N lines from the log file using seek-from-end
/// to avoid loading the entire file into memory.
pub fn read_log_tail(path: &PathBuf, max_lines: usize) -> Vec<LogEntry> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let file_len = match file.seek(SeekFrom::End(0)) {
        Ok(len) => len,
        Err(_) => return Vec::new(),
    };

    if file_len == 0 {
        return Vec::new();
    }

    // Read backwards in 64KB chunks until we have enough newlines
    let chunk_size: u64 = 65536;
    let mut tail_bytes = Vec::new();
    let mut newline_count = 0;
    let mut pos = file_len;

    while pos > 0 && newline_count <= max_lines {
        let read_size = std::cmp::min(chunk_size, pos);
        pos -= read_size;
        if file.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        let mut buf = vec![0u8; read_size as usize];
        if file.read_exact(&mut buf).is_err() {
            break;
        }
        // Count newlines in this chunk
        newline_count += buf.iter().filter(|&&b| b == b'\n').count();
        // Prepend chunk
        buf.append(&mut tail_bytes);
        tail_bytes = buf;
    }

    let text = String::from_utf8_lossy(&tail_bytes);
    let lines: Vec<&str> = text.lines().collect();

    // Take only the last max_lines
    let start = if lines.len() > max_lines {
        lines.len() - max_lines
    } else {
        0
    };

    lines[start..]
        .iter()
        .filter_map(|line| parse_log_line(line))
        .collect()
}

pub fn read_log_tail_capped(path: &PathBuf, max_lines: usize, max_bytes: u64) -> Vec<LogEntry> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let file_len = match file.seek(SeekFrom::End(0)) {
        Ok(len) => len,
        Err(_) => return Vec::new(),
    };

    if file_len == 0 {
        return Vec::new();
    }

    let start = file_len.saturating_sub(max_bytes);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }

    let mut tail_bytes = vec![0u8; (file_len - start) as usize];
    if file.read_exact(&mut tail_bytes).is_err() {
        return Vec::new();
    }

    let tail_slice = if start > 0 {
        match tail_bytes.iter().position(|&b| b == b'\n') {
            Some(index) if index + 1 < tail_bytes.len() => &tail_bytes[index + 1..],
            _ => &[][..],
        }
    } else {
        &tail_bytes[..]
    };

    let text = String::from_utf8_lossy(tail_slice);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);

    lines[start..]
        .iter()
        .filter_map(|line| parse_log_line(line))
        .collect()
}

pub fn redact_text(input: &str) -> String {
    let mut out = input.to_string();
    out = REDACT_PEM_PRIVATE_KEY_RE
        .replace_all(&out, "[REDACTED PRIVATE KEY]")
        .into_owned();
    out = REDACT_URL_CREDENTIALS_RE
        .replace_all(&out, "${1}[REDACTED]@")
        .into_owned();
    out = REDACT_AUTHORIZATION_BEARER_RE
        .replace_all(&out, "${1}[REDACTED]")
        .into_owned();
    out = REDACT_STANDALONE_BEARER_RE
        .replace_all(&out, "${1}[REDACTED]")
        .into_owned();
    out = REDACT_SECRET_KV_RE
        .replace_all(&out, "${1}[REDACTED]")
        .into_owned();

    for regex in [
        &*REDACT_GITHUB_TOKEN_RE,
        &*REDACT_GITHUB_PAT_TOKEN_RE,
        &*REDACT_HF_TOKEN_RE,
        &*REDACT_SLACK_TOKEN_RE,
        &*REDACT_SLACK_APP_TOKEN_RE,
        &*REDACT_GOOGLE_API_KEY_RE,
        &*REDACT_AWS_ACCESS_KEY_RE,
        &*REDACT_SK_ANT_TOKEN_RE,
        &*REDACT_SK_TOKEN_RE,
        &*REDACT_JWT_RE,
    ] {
        out = regex.replace_all(&out, "[REDACTED]").into_owned();
    }

    out = REDACT_HOME_PATH_RE.replace_all(&out, "~").into_owned();
    REDACT_WINDOWS_HOME_PATH_RE
        .replace_all(&out, "~")
        .into_owned()
}

pub fn truncate_utf8_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }

    let mut end = 0usize;
    for (index, ch) in input.char_indices() {
        let next = index + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }

    input[..end].to_string()
}

pub fn redact_and_truncate_browser_entry(entry: LogEntry) -> LogEntry {
    let message = truncate_utf8_bytes(&redact_text(&entry.message), LOG_ENTRY_MESSAGE_MAX_BYTES);
    let raw = entry
        .raw
        .as_deref()
        .map(redact_text)
        .map(|value| truncate_utf8_bytes(&value, LOG_ENTRY_MESSAGE_MAX_BYTES));

    LogEntry {
        message,
        raw,
        ..entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn read_log_tail_capped_does_not_read_entries_beyond_byte_cap() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("magic-context.log");
        let mut file = fs::File::create(&path).expect("create file");

        writeln!(
            file,
            "[2026-06-08T00:00:00Z] [magic-context][old] old entry"
        )
        .expect("write old");
        let filler = "x".repeat((LOG_TAIL_READ_CAP_BYTES as usize) + 128);
        write!(file, "{filler}").expect("write filler");
        writeln!(file).expect("newline");
        writeln!(
            file,
            "[2026-06-08T00:00:01Z] [magic-context][new] new entry"
        )
        .expect("write new");
        file.flush().expect("flush");

        let entries = read_log_tail_capped(&path, 10, LOG_TAIL_READ_CAP_BYTES);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id, "new");
        assert!(!entries.iter().any(|entry| entry.session_id == "old"));
    }

    #[test]
    fn redact_text_hides_required_token_header_jwt_and_path_patterns() {
        let input = concat!(
            "token ghp_1234567890abcdef Authorization: Bearer secret-token ",
            "Bearer abc.def.ghi jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature ",
            "home /home/naadir/project hf_abcdef slack xoxb-123-456 ",
            "google AIzaSy1234567890 aws AKIA1234567890ABCD ",
            "url https://user:pass@example.com"
        );

        let redacted = redact_text(input);
        for secret in [
            "ghp_1234567890abcdef",
            "secret-token",
            "abc.def.ghi",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
            "/home/naadir/project",
            "hf_abcdef",
            "xoxb-123-456",
            "AIzaSy1234567890",
            "AKIA1234567890ABCD",
            "https://user:pass@example.com",
        ] {
            assert!(!redacted.contains(secret), "secret leaked: {secret}");
        }
        assert!(redacted.contains("Authorization: Bearer [REDACTED]"));
        assert!(redacted.contains("Bearer [REDACTED]"));
        assert!(redacted.contains("~/project"));
        assert!(redacted.contains("https://[REDACTED]@example.com"));
    }

    #[test]
    fn redaction_happens_before_truncation() {
        let prefix = "a".repeat(LOG_ENTRY_MESSAGE_MAX_BYTES - 8);
        let input = format!("{prefix} ghp_1234567890abcdef");

        let output = truncate_utf8_bytes(&redact_text(&input), LOG_ENTRY_MESSAGE_MAX_BYTES);
        assert!(!output.contains("ghp_1234567890abcdef"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn truncate_utf8_bytes_is_utf8_safe() {
        let input = "🙂🙂🙂";
        let output = truncate_utf8_bytes(input, 5);
        assert_eq!(output, "🙂");
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());
    }
}
