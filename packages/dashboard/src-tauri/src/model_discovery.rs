use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;

use crate::process_ext::NoWindowExtTokio;

const PER_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(3);
const TOTAL_DISCOVERY_BUDGET: Duration = Duration::from_secs(10);
const STDOUT_CAP_BYTES: usize = 128 * 1024;
const STDERR_CAP_BYTES: usize = 8 * 1024;
const MAX_MODELS: usize = 1000;
const MAX_MODEL_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscoveryKind {
    Opencode,
    Pi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateStatus {
    Success,
    SpawnFailed,
    WaitFailed,
    NonZeroExit,
    TimedOut,
    OutputCapExceeded,
}

#[derive(Debug)]
struct CandidateRunResult {
    status: CandidateStatus,
    stdout: Vec<u8>,
    stdout_bytes: usize,
    stderr_bytes: usize,
}

pub async fn discover_opencode_models() -> Vec<String> {
    discover_models(DiscoveryKind::Opencode).await
}

pub async fn discover_pi_models() -> Vec<String> {
    discover_models(DiscoveryKind::Pi).await
}

pub fn parse_pi_models_output(text: &str) -> Vec<String> {
    let mut models = BTreeSet::new();

    for raw_line in strip_ansi_pi_output(text).lines() {
        let line = raw_line
            .trim()
            .trim_start_matches(|ch| matches!(ch, '\u{2022}' | '*' | '-'))
            .trim();
        if line.is_empty() || line.to_ascii_lowercase().contains("usage:") {
            continue;
        }

        let cols: Vec<&str> = line.split_whitespace().collect();
        let first = cols.first().map(|s| s.trim_end_matches(',')).unwrap_or("");

        if first.contains('/') {
            if !first.starts_with("http://") && !first.starts_with("https://") {
                models.insert(first.to_string());
            }
            continue;
        }

        let provider = first;
        let model = cols.get(1).map(|s| s.trim_end_matches(',')).unwrap_or("");
        if provider.eq_ignore_ascii_case("provider") && model.eq_ignore_ascii_case("model") {
            continue;
        }
        if pi_provider_token_ok(provider) && pi_model_token_ok(model) {
            models.insert(format!("{provider}/{model}"));
        }
    }

    models.into_iter().collect()
}

async fn discover_models(kind: DiscoveryKind) -> Vec<String> {
    let started = Instant::now();

    for bin in candidate_bins(kind).await {
        let elapsed = started.elapsed();
        let Some(remaining) = TOTAL_DISCOVERY_BUDGET.checked_sub(elapsed) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }

        let timeout = remaining.min(PER_CANDIDATE_TIMEOUT);
        let result = run_candidate(&bin, candidate_arg(kind), timeout).await;

        eprintln!(
            "[model-discovery] kind={:?} candidate={} status={:?} stdout_bytes={} stderr_bytes={}",
            kind,
            result_safe_candidate_name(&bin),
            result.status,
            result.stdout_bytes,
            result.stderr_bytes,
        );

        if result.status == CandidateStatus::Success {
            let parsed = parse_models(kind, &String::from_utf8_lossy(&result.stdout));
            return sanitize_models(parsed);
        }
    }

    Vec::new()
}

fn parse_models(kind: DiscoveryKind, stdout: &str) -> Vec<String> {
    match kind {
        DiscoveryKind::Opencode => stdout.lines().map(str::to_string).collect(),
        DiscoveryKind::Pi => parse_pi_models_output(stdout),
    }
}

fn sanitize_models(models: Vec<String>) -> Vec<String> {
    let mut sanitized = BTreeSet::new();

    for model in models {
        let cleaned: String = model.chars().filter(|ch| !ch.is_control()).collect();
        let trimmed = cleaned.trim();
        if trimmed.is_empty() || trimmed.as_bytes().len() > MAX_MODEL_ID_BYTES {
            continue;
        }
        sanitized.insert(trimmed.to_string());
        if sanitized.len() >= MAX_MODELS {
            break;
        }
    }

    sanitized.into_iter().collect()
}

async fn run_candidate(bin: &str, arg: &str, timeout: Duration) -> CandidateRunResult {
    let mut command = tokio::process::Command::new(bin);
    command
        .arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .no_window();

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return CandidateRunResult {
                status: CandidateStatus::SpawnFailed,
                stdout: Vec::new(),
                stdout_bytes: 0,
                stderr_bytes: 0,
            };
        }
    };

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let stdout_task = tokio::spawn(async move {
        match stdout_handle {
            Some(stdout) => read_capped(stdout, STDOUT_CAP_BYTES + 1).await,
            None => Vec::new(),
        }
    });
    let stderr_task = tokio::spawn(async move {
        match stderr_handle {
            Some(stderr) => read_capped(stderr, STDERR_CAP_BYTES + 1).await,
            None => Vec::new(),
        }
    });

    let wait_result = tokio::time::timeout(timeout, child.wait()).await;
    let status = match wait_result {
        Ok(Ok(exit_status)) => {
            if exit_status.success() {
                CandidateStatus::Success
            } else {
                CandidateStatus::NonZeroExit
            }
        }
        Ok(Err(_)) => CandidateStatus::WaitFailed,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            CandidateStatus::TimedOut
        }
    };

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();
    let stdout_bytes = stdout.len();
    let stderr_bytes = stderr.len();

    let status = if matches!(
        status,
        CandidateStatus::Success | CandidateStatus::NonZeroExit
    ) && (stdout_bytes > STDOUT_CAP_BYTES || stderr_bytes > STDERR_CAP_BYTES)
    {
        CandidateStatus::OutputCapExceeded
    } else {
        status
    };

    CandidateRunResult {
        status,
        stdout,
        stdout_bytes,
        stderr_bytes,
    }
}

async fn read_capped<R>(reader: R, cap: usize) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let _ = reader.take(cap as u64).read_to_end(&mut buffer).await;
    buffer
}

fn candidate_arg(kind: DiscoveryKind) -> &'static str {
    match kind {
        DiscoveryKind::Opencode => "models",
        DiscoveryKind::Pi => "--list-models",
    }
}

async fn candidate_bins(kind: DiscoveryKind) -> Vec<String> {
    #[cfg(test)]
    if let Some(candidates) = test_candidate_override(kind) {
        return candidates;
    }

    let tool = candidate_tool(kind);
    let mut candidates = base_candidate_bins(kind);

    if let Some(path) = run_via_login_shell(format!("command -v {tool}")).await {
        candidates.push(path);
    }
    if let Some(path) = resolve_via_where(tool).await {
        candidates.push(path);
    }
    candidates.push(tool.to_string());

    candidates
}

fn base_candidate_bins(kind: DiscoveryKind) -> Vec<String> {
    if cfg!(target_os = "windows") {
        let home = std::env::var("USERPROFILE").unwrap_or_default();
        return match kind {
            DiscoveryKind::Opencode => vec![format!("{}\\.opencode\\bin\\opencode.exe", home)],
            DiscoveryKind::Pi => vec![format!("{}\\.pi\\bin\\pi.exe", home)],
        };
    }

    let home = std::env::var("HOME").unwrap_or_default();
    match kind {
        DiscoveryKind::Opencode => vec![
            format!("{}/.opencode/bin/opencode", home),
            format!("{}/.local/bin/opencode", home),
            "/usr/local/bin/opencode".to_string(),
            "/opt/homebrew/bin/opencode".to_string(),
        ],
        DiscoveryKind::Pi => vec![
            format!("{}/.pi/bin/pi", home),
            format!("{}/.local/bin/pi", home),
            "/usr/local/bin/pi".to_string(),
            "/opt/homebrew/bin/pi".to_string(),
        ],
    }
}

fn candidate_tool(kind: DiscoveryKind) -> &'static str {
    match kind {
        DiscoveryKind::Opencode => "opencode",
        DiscoveryKind::Pi => "pi",
    }
}

#[cfg(unix)]
async fn run_via_login_shell(command: String) -> Option<String> {
    let shell = std::env::var("SHELL").ok()?;
    let fut = tokio::process::Command::new(&shell)
        .arg("-l")
        .arg("-c")
        .arg(&command)
        .no_window()
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(PER_CANDIDATE_TIMEOUT, fut).await {
        Ok(Ok(output)) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            pick_first_line(&stdout)
        }
        _ => None,
    }
}

#[cfg(not(unix))]
async fn run_via_login_shell(_command: String) -> Option<String> {
    None
}

fn pick_first_line(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().next()?.trim().to_string();
    if first_line.is_empty() {
        None
    } else {
        Some(first_line)
    }
}

#[cfg(windows)]
async fn resolve_via_where(tool: &str) -> Option<String> {
    let fut = tokio::process::Command::new("where.exe")
        .arg(tool)
        .no_window()
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(PER_CANDIDATE_TIMEOUT, fut).await {
        Ok(Ok(output)) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            pick_first_line(&stdout)
        }
        _ => None,
    }
}

#[cfg(not(windows))]
async fn resolve_via_where(_tool: &str) -> Option<String> {
    None
}

fn strip_ansi_pi_output(text: &str) -> String {
    let re = regex::Regex::new(r"\x1b\[[0-9;]*m").expect("ansi strip regex");
    re.replace_all(text, "").into_owned()
}

fn pi_provider_token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn pi_model_token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
}

fn result_safe_candidate_name(bin: &str) -> &str {
    std::path::Path::new(bin)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(bin)
}

#[cfg(test)]
static TEST_OPENCODE_CANDIDATES: std::sync::Mutex<Option<Vec<String>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
static TEST_PI_CANDIDATES: std::sync::Mutex<Option<Vec<String>>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn test_candidate_override(kind: DiscoveryKind) -> Option<Vec<String>> {
    let guard = match kind {
        DiscoveryKind::Opencode => TEST_OPENCODE_CANDIDATES.lock().ok()?,
        DiscoveryKind::Pi => TEST_PI_CANDIDATES.lock().ok()?,
    };
    guard.clone()
}

#[cfg(test)]
pub(crate) fn set_test_candidates(kind: &str, candidates: Option<Vec<String>>) {
    let target = match kind {
        "opencode" => &TEST_OPENCODE_CANDIDATES,
        "pi" => &TEST_PI_CANDIDATES,
        _ => panic!("unknown discovery kind: {kind}"),
    };
    *target.lock().expect("test candidate lock") = candidates;
}

#[cfg(test)]
mod tests {
    use super::{parse_pi_models_output, sanitize_models, MAX_MODELS, MAX_MODEL_ID_BYTES};

    #[test]
    fn parse_pi_models_output_extracts_provider_model_pairs() {
        let parsed = parse_pi_models_output(
            "PROVIDER MODEL STATUS\nopenai gpt-4o ready\nanthropic claude-sonnet online\n",
        );
        assert_eq!(parsed, vec!["anthropic/claude-sonnet", "openai/gpt-4o"]);
    }

    #[test]
    fn sanitize_models_drops_controls_long_ids_and_dedupes_stably() {
        let long = "x".repeat(257);
        let mut raw = vec![
            " alpha ".to_string(),
            "alpha".to_string(),
            "be\u{0007}ta".to_string(),
            "\n\t".to_string(),
            long,
        ];
        raw.extend((0..1100).map(|idx| format!("model-{idx}")));

        let sanitized = sanitize_models(raw);
        assert_eq!(sanitized[0], "alpha");
        assert!(sanitized.contains(&"beta".to_string()));
        assert_eq!(sanitized.len(), MAX_MODELS);
        assert!(!sanitized
            .iter()
            .any(|model| model.as_bytes().len() > MAX_MODEL_ID_BYTES));
    }
}
