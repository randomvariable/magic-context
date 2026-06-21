//! OpenAI-compatible embedding endpoint probe + config-variable substitution.
//!
//! Mirrors the Node implementations in
//!   packages/plugin/src/features/magic-context/memory/embedding-probe.ts
//!   packages/plugin/src/config/variable.ts
//!
//! The dashboard and doctor perform the same network probe and classification,
//! so a failure seen in one tool looks the same in the other. Users pick
//! whichever tool they prefer without running into "it works in doctor but
//! fails in the dashboard" surprises.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use reqwest::Url;
use serde::Serialize;

/// Structured probe outcome. Matches the kinds produced by the Node probe so
/// frontend messaging can key off the same categories.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmbeddingProbeOutcome {
    /// 2xx with a valid `data[0].embedding` float array.
    Ok {
        status: u16,
        dimensions: Option<usize>,
    },
    /// 401 / 403 — credentials rejected.
    AuthFailed { status: u16, preview: String },
    /// 404 / 405 or 2xx without an embedding body — endpoint doesn't serve
    /// embeddings (wrong URL, or provider doesn't offer the API).
    EndpointUnsupported { status: u16, preview: String },
    /// Other non-2xx status.
    HttpError { status: u16, preview: String },
    /// Connection failed, DNS failed, TLS failed, etc.
    NetworkError { message: String },
    /// Request took longer than `timeout_ms`.
    Timeout { timeout_ms: u64 },
    /// Endpoint URL is missing `http://` or `https://` prefix.
    InvalidScheme { endpoint: String },
    /// Config contains `{env:VAR}` / `{file:path}` tokens that did not
    /// resolve — the dashboard runs its own process with its own environment,
    /// so env vars set only in the user's shell won't be visible here.
    UnresolvedToken {
        /// Which field carries the token (e.g., "api_key", "endpoint").
        field: String,
        /// The unresolved token (e.g., "{env:EMBED_KEY}"). Safe to surface —
        /// users need to know which var is missing.
        token: String,
    },
    /// Resolved config value is invalid after `{env:...}` / `{file:...}` expansion.
    InvalidConfigField { field: String, message: String },
}

/// Options passed to the Rust probe. Mirrors the Node `EmbeddingProbeOptions`.
#[derive(Debug, Clone)]
pub struct EmbeddingProbeOptions {
    pub endpoint: String,
    pub model: String,
    pub api_key: Option<String>,
    /// Optional `input_type` body field — required by some providers (NVIDIA NIM).
    pub input_type: Option<String>,
    /// Optional `truncate` body field (e.g. NVIDIA NIM).
    pub truncate: Option<String>,
    pub timeout_ms: u64,
}

const MAX_PREVIEW_CHARS: usize = 240;
const BROWSER_PROBE_RESPONSE_MAX_BYTES: usize = 512 * 1024;
const BROWSER_PROBE_CONNECT_TIMEOUT_MS: u64 = 3_000;

/// Substitute `{env:VAR}` and `{file:path}` tokens in a single value string.
///
/// The plugin's Node substitution operates on raw config text before JSONC
/// parsing; the dashboard operates on individual already-parsed field values
/// directly from the form. Both semantics are the same: missing env vars
/// resolve to the empty string (we don't know whether the user *wanted* an
/// empty auth header or forgot to export the var), and missing files do the
/// same. We report whether any substitution left a residual token so the
/// probe can classify `{env:X}` residue as an actionable outcome.
///
/// `config_dir` is used to resolve relative `{file:./path}` references. For
/// virtual/unit-test callers pass `None` — `~/...` paths still work.
///
/// Returns `(substituted_value, residual_token)`. If any token failed to
/// resolve, `residual_token` holds the first one (for error reporting) —
/// otherwise `None`.
pub fn substitute_value(raw: &str, config_dir: Option<&Path>) -> (String, Option<String>) {
    let mut out = String::with_capacity(raw.len());
    let mut residual: Option<String> = None;
    let bytes = raw.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Look for `{env:` or `{file:` at this position.
        if bytes[i] == b'{' {
            if bytes[i..].starts_with(b"{env:") {
                let start = i + b"{env:".len();
                if let Some(rel_end) = raw[start..].find('}') {
                    let end = start + rel_end;
                    let var_name = raw[start..end].trim();
                    let token = &raw[i..=end]; // includes closing }
                    match std::env::var(var_name) {
                        Ok(val) if !val.is_empty() => {
                            out.push_str(&val);
                        }
                        _ => {
                            // Unresolved — leave the token in place so the
                            // caller can detect it and surface a specific
                            // "export your env var" message.
                            if residual.is_none() {
                                residual = Some(token.to_string());
                            }
                            out.push_str(token);
                        }
                    }
                    i = end + 1;
                    continue;
                }
            } else if bytes[i..].starts_with(b"{file:") {
                let start = i + b"{file:".len();
                if let Some(rel_end) = raw[start..].find('}') {
                    let end = start + rel_end;
                    let raw_path = raw[start..end].trim();
                    let token = &raw[i..=end];
                    match resolve_and_read_file(raw_path, config_dir) {
                        Some(contents) => {
                            // Escape for safe embedding. Because we're
                            // operating on a parsed field (not raw JSON), we
                            // don't need JSON-escape here — the value will be
                            // sent as-is over the wire (e.g., as a bearer
                            // token). Trim for parity with the Node
                            // implementation which trims file contents.
                            out.push_str(contents.trim());
                        }
                        None => {
                            if residual.is_none() {
                                residual = Some(token.to_string());
                            }
                            out.push_str(token);
                        }
                    }
                    i = end + 1;
                    continue;
                }
            }
        }

        // Not a token start — copy byte verbatim. Using bytes keeps this
        // O(n); we reassemble a valid UTF-8 string at the end because
        // tokens never straddle UTF-8 boundaries (they're ASCII-only).
        let ch = raw[i..].chars().next().expect("in-range char");
        out.push(ch);
        i += ch.len_utf8();
    }

    (out, residual)
}

fn resolve_and_read_file(raw_path: &str, config_dir: Option<&Path>) -> Option<String> {
    use std::path::PathBuf;

    let path: PathBuf = if let Some(rest) = raw_path.strip_prefix("~/") {
        let home = dirs::home_dir()?;
        home.join(rest)
    } else if Path::new(raw_path).is_absolute() {
        PathBuf::from(raw_path)
    } else {
        match config_dir {
            Some(dir) => dir.join(raw_path),
            None => PathBuf::from(raw_path),
        }
    };

    if !path.exists() {
        return None;
    }
    std::fs::read_to_string(&path).ok()
}

/// POST `{model, input}` to `${endpoint}/embeddings` and classify the outcome.
pub async fn probe_embedding_endpoint(options: EmbeddingProbeOptions) -> EmbeddingProbeOutcome {
    let endpoint = options.endpoint.trim().trim_end_matches('/').to_string();
    if endpoint.is_empty() || !(endpoint.starts_with("https://") || endpoint.starts_with("http://"))
    {
        return EmbeddingProbeOutcome::InvalidScheme {
            endpoint: options.endpoint.clone(),
        };
    }

    let url = format!("{}/embeddings", endpoint);

    // `.no_proxy()` is deliberate: by default reqwest auto-detects macOS
    // / Windows system proxy settings, which produces a confusing failure
    // mode where `doctor` works (Node's fetch ignores system proxies and
    // only honors HTTP_PROXY/HTTPS_PROXY env vars) but the dashboard
    // tries to route the same localhost URL through whatever the user
    // has configured in System Settings → Network → Proxies. Setting
    // no_proxy() here aligns the dashboard probe with Node's behavior so
    // both surfaces classify the same endpoint the same way. Users who
    // genuinely want to route embedding traffic through a proxy can
    // expose that as an explicit config field later if needed.
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(options.timeout_ms))
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return EmbeddingProbeOutcome::NetworkError {
                message: format!("Failed to create HTTP client: {}", e),
            };
        }
    };

    let mut body = serde_json::json!({
        "model": options.model,
        "input": "magic-context probe",
    });
    // Optional provider-specific fields (e.g. NVIDIA NIM requires input_type).
    // Added only when set so standard OpenAI endpoints are unaffected.
    if let Some(map) = body.as_object_mut() {
        if let Some(input_type) = options
            .input_type
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            map.insert(
                "input_type".to_string(),
                serde_json::Value::String(input_type.to_string()),
            );
        }
        if let Some(truncate) = options
            .truncate
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            map.insert(
                "truncate".to_string(),
                serde_json::Value::String(truncate.to_string()),
            );
        }
    }

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body);

    if let Some(key) = options.api_key.as_deref() {
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", trimmed));
        }
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // reqwest marks timeouts specifically — surface them so the user
            // gets actionable "check endpoint URL / network" wording rather
            // than the generic connection-failed message.
            if e.is_timeout() {
                return EmbeddingProbeOutcome::Timeout {
                    timeout_ms: options.timeout_ms,
                };
            }
            return EmbeddingProbeOutcome::NetworkError {
                // reqwest's Display only renders the top-level message
                // (`error sending request for url (...)`) and drops the
                // underlying cause. Walk the source chain so users see the
                // actual failure (connection refused, DNS, TLS handshake,
                // etc.) instead of just the URL.
                message: format_error_with_causes(&e),
            };
        }
    };

    let status = response.status();
    let status_u16 = status.as_u16();

    if status.is_success() {
        // Parse body and verify shape. OpenRouter, for example, may return
        // 200 with a chat-style body when the embeddings route is not
        // supported — we want to catch that instead of reporting success.
        let body_text = response.text().await.unwrap_or_default();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body_text);
        let preview = truncate_preview(&body_text);
        match parsed {
            Ok(value) => match extract_dimensions(&value) {
                Some(dims) => EmbeddingProbeOutcome::Ok {
                    status: status_u16,
                    dimensions: Some(dims),
                },
                None => EmbeddingProbeOutcome::EndpointUnsupported {
                    status: status_u16,
                    preview,
                },
            },
            Err(_) => {
                // 2xx but non-JSON body — definitely not an embeddings response.
                EmbeddingProbeOutcome::EndpointUnsupported {
                    status: status_u16,
                    preview,
                }
            }
        }
    } else {
        let body_text = response.text().await.unwrap_or_default();
        let preview = truncate_preview(&body_text);
        match status_u16 {
            401 | 403 => EmbeddingProbeOutcome::AuthFailed {
                status: status_u16,
                preview,
            },
            404 | 405 => EmbeddingProbeOutcome::EndpointUnsupported {
                status: status_u16,
                preview,
            },
            _ => EmbeddingProbeOutcome::HttpError {
                status: status_u16,
                preview,
            },
        }
    }
}

/// Browser-safe embedding probe. Applies tighter SSRF, redirect, body-size,
/// and secret-redaction controls than the desktop command surface.
pub async fn probe_embedding_endpoint_browser(
    options: EmbeddingProbeOptions,
) -> EmbeddingProbeOutcome {
    let prepared = match prepare_browser_probe_options(options) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };

    let validated = match validate_browser_endpoint(&prepared.endpoint).await {
        Ok(validated) => validated,
        Err(outcome) => return sanitize_outcome(outcome, prepared.api_key.as_deref()),
    };

    let client = match build_browser_probe_client(&validated, prepared.timeout_ms) {
        Ok(client) => client,
        Err(error) => {
            return sanitize_outcome(
                EmbeddingProbeOutcome::NetworkError {
                    message: format!("Failed to create HTTP client: {error}"),
                },
                prepared.api_key.as_deref(),
            );
        }
    };

    let mut body = serde_json::json!({
        "model": prepared.model,
        "input": "magic-context probe",
    });
    if let Some(map) = body.as_object_mut() {
        if let Some(input_type) = prepared.input_type.as_deref() {
            map.insert(
                "input_type".to_string(),
                serde_json::Value::String(input_type.to_string()),
            );
        }
        if let Some(truncate) = prepared.truncate.as_deref() {
            map.insert(
                "truncate".to_string(),
                serde_json::Value::String(truncate.to_string()),
            );
        }
    }

    let mut req = client
        .post(validated.embeddings_url)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(api_key) = prepared.api_key.as_deref() {
        req = req.header("Authorization", format!("Bearer {api_key}"));
    }

    let response = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            if error.is_timeout() {
                return EmbeddingProbeOutcome::Timeout {
                    timeout_ms: prepared.timeout_ms,
                };
            }
            return sanitize_outcome(
                EmbeddingProbeOutcome::NetworkError {
                    message: format_error_with_causes(&error),
                },
                prepared.api_key.as_deref(),
            );
        }
    };

    let status = response.status();
    let status_u16 = status.as_u16();

    if status.is_redirection() {
        return sanitize_outcome(
            EmbeddingProbeOutcome::HttpError {
                status: status_u16,
                preview: "redirect responses are not followed".to_string(),
            },
            prepared.api_key.as_deref(),
        );
    }

    if response
        .content_length()
        .is_some_and(|len| len > BROWSER_PROBE_RESPONSE_MAX_BYTES as u64)
    {
        return sanitize_outcome(
            oversized_response_outcome(status_u16),
            prepared.api_key.as_deref(),
        );
    }

    let body_bytes = match read_response_body_capped(response).await {
        Ok(bytes) => bytes,
        Err(outcome) => {
            return sanitize_outcome(outcome, prepared.api_key.as_deref());
        }
    };

    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();
    if status.is_success() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&body_bytes);
        match parsed {
            Ok(value) => match extract_dimensions(&value) {
                Some(dimensions) => EmbeddingProbeOutcome::Ok {
                    status: status_u16,
                    dimensions: Some(dimensions),
                },
                None => sanitize_outcome(
                    EmbeddingProbeOutcome::EndpointUnsupported {
                        status: status_u16,
                        preview: truncate_preview(&body_text),
                    },
                    prepared.api_key.as_deref(),
                ),
            },
            Err(_) => sanitize_outcome(
                EmbeddingProbeOutcome::EndpointUnsupported {
                    status: status_u16,
                    preview: truncate_preview(&body_text),
                },
                prepared.api_key.as_deref(),
            ),
        }
    } else {
        let preview = truncate_preview(&body_text);
        let outcome = match status_u16 {
            401 | 403 => EmbeddingProbeOutcome::AuthFailed {
                status: status_u16,
                preview,
            },
            404 | 405 => EmbeddingProbeOutcome::EndpointUnsupported {
                status: status_u16,
                preview,
            },
            _ => EmbeddingProbeOutcome::HttpError {
                status: status_u16,
                preview,
            },
        };
        sanitize_outcome(outcome, prepared.api_key.as_deref())
    }
}

#[derive(Debug)]
struct ValidatedBrowserEndpoint {
    embeddings_url: String,
    resolve_domain: Option<String>,
    resolved_addrs: Vec<SocketAddr>,
}

fn build_browser_probe_client(
    validated: &ValidatedBrowserEndpoint,
    timeout_ms: u64,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(BROWSER_PROBE_CONNECT_TIMEOUT_MS))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();

    if let Some(domain) = validated.resolve_domain.as_deref() {
        builder = builder.resolve_to_addrs(domain, &validated.resolved_addrs);
    }

    builder.build()
}

async fn validate_browser_endpoint(
    endpoint: &str,
) -> Result<ValidatedBrowserEndpoint, EmbeddingProbeOutcome> {
    if endpoint.is_empty() || !(endpoint.starts_with("https://") || endpoint.starts_with("http://"))
    {
        return Err(EmbeddingProbeOutcome::InvalidScheme {
            endpoint: endpoint.to_string(),
        });
    }

    let url = Url::parse(endpoint).map_err(|_| EmbeddingProbeOutcome::InvalidScheme {
        endpoint: endpoint.to_string(),
    })?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(browser_ssrf_rejection(
            "only http and https endpoints are allowed",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(browser_ssrf_rejection(
            "endpoint URL must not include userinfo",
        ));
    }
    if url.query().is_some() {
        return Err(browser_ssrf_rejection(
            "endpoint URL must not include query parameters",
        ));
    }
    if url.fragment().is_some() {
        return Err(browser_ssrf_rejection(
            "endpoint URL must not include fragments",
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| browser_ssrf_rejection("endpoint URL must include a host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let is_exact_loopback = is_exact_loopback_host(host);

    if scheme == "http" && !is_exact_loopback {
        return Err(browser_ssrf_rejection(
            "http endpoints must use localhost, 127.0.0.1, or [::1]",
        ));
    }

    let (resolve_domain, resolved_addrs) = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_disallowed_ip(ip, !is_exact_loopback) {
            return Err(browser_ssrf_rejection(
                "endpoint host resolves to a disallowed address",
            ));
        }
        (None, Vec::new())
    } else {
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| EmbeddingProbeOutcome::NetworkError {
                message: format!("DNS resolution failed: {error}"),
            })?;
        let mut validated_addrs = Vec::new();
        let mut saw_any = false;
        for addr in addrs {
            saw_any = true;
            if is_disallowed_ip(addr.ip(), !is_exact_loopback) {
                return Err(browser_ssrf_rejection(
                    "endpoint host resolves to a disallowed address",
                ));
            }
            validated_addrs.push(addr);
        }
        if !saw_any {
            return Err(EmbeddingProbeOutcome::NetworkError {
                message: "DNS resolution returned no addresses".to_string(),
            });
        }
        (Some(host.to_ascii_lowercase()), validated_addrs)
    };

    Ok(ValidatedBrowserEndpoint {
        embeddings_url: format!("{}/embeddings", endpoint.trim_end_matches('/')),
        resolve_domain,
        resolved_addrs,
    })
}

fn prepare_browser_probe_options(
    mut options: EmbeddingProbeOptions,
) -> Result<EmbeddingProbeOptions, EmbeddingProbeOutcome> {
    let field_specs = [
        ("endpoint", options.endpoint.as_str()),
        ("model", options.model.as_str()),
        ("api_key", options.api_key.as_deref().unwrap_or_default()),
        (
            "input_type",
            options.input_type.as_deref().unwrap_or_default(),
        ),
        ("truncate", options.truncate.as_deref().unwrap_or_default()),
    ];
    for (field, raw) in field_specs {
        if let Some(token) = find_file_token(raw) {
            return Err(EmbeddingProbeOutcome::UnresolvedToken {
                field: field.to_string(),
                token,
            });
        }
    }

    let (endpoint, endpoint_residual) = substitute_value(&options.endpoint, None);
    let (model, model_residual) = substitute_value(&options.model, None);
    let (api_key, api_key_residual) = match options.api_key.as_deref() {
        Some(value) => {
            let (resolved, residual) = substitute_value(value, None);
            (Some(resolved), residual)
        }
        None => (None, None),
    };
    let (input_type, input_type_residual) = match options.input_type.as_deref() {
        Some(value) => {
            let (resolved, residual) = substitute_value(value, None);
            (Some(resolved), residual)
        }
        None => (None, None),
    };
    let (truncate, truncate_residual) = match options.truncate.as_deref() {
        Some(value) => {
            let (resolved, residual) = substitute_value(value, None);
            (Some(resolved), residual)
        }
        None => (None, None),
    };

    for (field, residual) in [
        ("endpoint", endpoint_residual),
        ("model", model_residual),
        ("api_key", api_key_residual),
        ("input_type", input_type_residual),
        ("truncate", truncate_residual),
    ] {
        if let Some(token) = residual {
            return Err(EmbeddingProbeOutcome::UnresolvedToken {
                field: field.to_string(),
                token,
            });
        }
    }

    options.endpoint = endpoint.trim().to_string();
    options.model = model.trim().to_string();
    options.api_key = api_key
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    options.input_type = input_type
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    options.truncate = truncate
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    validate_resolved_browser_probe_field(&options.endpoint, "endpoint", 2048, true)?;
    validate_resolved_browser_probe_field(&options.model, "model", 512, true)?;
    if let Some(api_key) = options.api_key.as_deref() {
        validate_resolved_browser_probe_field(api_key, "apiKey", 8192, false)?;
    }
    if let Some(input_type) = options.input_type.as_deref() {
        validate_resolved_browser_probe_field(input_type, "inputType", 128, true)?;
    }
    if let Some(truncate) = options.truncate.as_deref() {
        validate_resolved_browser_probe_field(truncate, "truncate", 128, true)?;
    }

    Ok(options)
}

fn validate_resolved_browser_probe_field(
    value: &str,
    field: &str,
    max_bytes: usize,
    reject_all_controls: bool,
) -> Result<(), EmbeddingProbeOutcome> {
    let has_disallowed_control = if reject_all_controls {
        value.chars().any(char::is_control)
    } else {
        value
            .chars()
            .any(|ch| matches!(ch, '\r' | '\n' | '\0') || (ch.is_control() && ch != '\t'))
    };
    if has_disallowed_control {
        return Err(EmbeddingProbeOutcome::InvalidConfigField {
            field: field.to_string(),
            message: "contains control characters".to_string(),
        });
    }
    if value.len() > max_bytes {
        return Err(EmbeddingProbeOutcome::InvalidConfigField {
            field: field.to_string(),
            message: format!("exceeds max length of {max_bytes} bytes"),
        });
    }
    if contains_file_token(value) {
        return Err(EmbeddingProbeOutcome::InvalidConfigField {
            field: field.to_string(),
            message: "contains unsupported {file:...} token".to_string(),
        });
    }
    Ok(())
}

fn contains_file_token(input: &str) -> bool {
    input.contains("{file:")
}

fn display_token_for_error(token: &str) -> String {
    if token.starts_with("{file:") {
        "{file:...}".to_string()
    } else {
        token.to_string()
    }
}

async fn read_response_body_capped(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, EmbeddingProbeOutcome> {
    let mut body = Vec::new();
    while let Some(chunk) =
        response
            .chunk()
            .await
            .map_err(|error| EmbeddingProbeOutcome::NetworkError {
                message: format!("failed to read response body: {error}"),
            })?
    {
        if body.len() + chunk.len() > BROWSER_PROBE_RESPONSE_MAX_BYTES {
            return Err(oversized_response_outcome(response.status().as_u16()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn oversized_response_outcome(status: u16) -> EmbeddingProbeOutcome {
    if (200..300).contains(&status) {
        EmbeddingProbeOutcome::EndpointUnsupported {
            status,
            preview: "response too large".to_string(),
        }
    } else {
        EmbeddingProbeOutcome::HttpError {
            status,
            preview: "response too large".to_string(),
        }
    }
}

fn browser_ssrf_rejection(reason: &str) -> EmbeddingProbeOutcome {
    EmbeddingProbeOutcome::NetworkError {
        message: format!("Outbound probe blocked: {reason}"),
    }
}

fn sanitize_outcome(
    outcome: EmbeddingProbeOutcome,
    api_key: Option<&str>,
) -> EmbeddingProbeOutcome {
    match outcome {
        EmbeddingProbeOutcome::Ok { status, dimensions } => {
            EmbeddingProbeOutcome::Ok { status, dimensions }
        }
        EmbeddingProbeOutcome::AuthFailed { status, preview } => {
            EmbeddingProbeOutcome::AuthFailed {
                status,
                preview: sanitize_text(&preview, api_key),
            }
        }
        EmbeddingProbeOutcome::EndpointUnsupported { status, preview } => {
            EmbeddingProbeOutcome::EndpointUnsupported {
                status,
                preview: sanitize_text(&preview, api_key),
            }
        }
        EmbeddingProbeOutcome::HttpError { status, preview } => EmbeddingProbeOutcome::HttpError {
            status,
            preview: sanitize_text(&preview, api_key),
        },
        EmbeddingProbeOutcome::NetworkError { message } => EmbeddingProbeOutcome::NetworkError {
            message: sanitize_text(&message, api_key),
        },
        EmbeddingProbeOutcome::Timeout { timeout_ms } => {
            EmbeddingProbeOutcome::Timeout { timeout_ms }
        }
        EmbeddingProbeOutcome::InvalidScheme { endpoint } => EmbeddingProbeOutcome::InvalidScheme {
            endpoint: sanitize_text(&endpoint, api_key),
        },
        EmbeddingProbeOutcome::UnresolvedToken { field, token } => {
            EmbeddingProbeOutcome::UnresolvedToken {
                field,
                token: display_token_for_error(&token),
            }
        }
        EmbeddingProbeOutcome::InvalidConfigField { field, message } => {
            EmbeddingProbeOutcome::InvalidConfigField { field, message }
        }
    }
}

fn sanitize_text(input: &str, api_key: Option<&str>) -> String {
    use regex::Regex;

    let mut text = input
        .chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>();

    if let Some(api_key) = api_key.filter(|value| !value.is_empty()) {
        text = text.replace(api_key, "[redacted]");
    }

    let patterns = [
        (
            r#"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s"']+"#,
            "$1[redacted]",
        ),
        (
            r"(?i)(bearer\s+)(sk(?:-ant)?-[A-Za-z0-9_\-]+)",
            "$1[redacted]",
        ),
        (r"\bsk-ant-[A-Za-z0-9_\-]+\b", "[redacted]"),
        (r"\bsk-[A-Za-z0-9_\-]+\b", "[redacted]"),
        (
            r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
            "[redacted]",
        ),
        (
            r#"(?i)(\b(?:api[_-]?key|apikey|token|secret|authorization)\b\s*[:=]\s*["']?)[^\s,"'}]+"#,
            "$1[redacted]",
        ),
        (r"(?i)([a-z][a-z0-9+\-.]*://)[^/@\s]+@", "$1[redacted]@"),
    ];

    for (pattern, replacement) in patterns {
        let regex = Regex::new(pattern).expect("valid redaction regex");
        text = regex.replace_all(&text, replacement).into_owned();
    }

    text
}

fn find_file_token(raw: &str) -> Option<String> {
    let start = raw.find("{file:")?;
    let rest = &raw[start..];
    let end = rest.find('}')?;
    Some(rest[..=end].to_string())
}

fn is_exact_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn is_disallowed_ip(ip: std::net::IpAddr, reject_loopback: bool) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => is_disallowed_ipv4(ipv4, reject_loopback),
        std::net::IpAddr::V6(ipv6) => is_disallowed_ipv6(ipv6, reject_loopback),
    }
}

fn is_disallowed_ipv4(ip: std::net::Ipv4Addr, reject_loopback: bool) -> bool {
    if reject_loopback && ip.is_loopback() {
        return true;
    }
    if ip.is_unspecified()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
    {
        return true;
    }
    let [a, b, c, _d] = ip.octets();
    matches!(
        (a, b, c),
        (0, _, _)
            | (100, 64..=127, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
    ) || a >= 224
}

fn is_disallowed_ipv6(ip: std::net::Ipv6Addr, reject_loopback: bool) -> bool {
    if (reject_loopback && ip.is_loopback()) || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let segments = ip.segments();
    let first = segments[0];
    let top_byte = (first >> 8) as u8;
    if (top_byte & 0xfe) == 0xfc {
        return true;
    }
    if (top_byte == 0xfe) && ((first & 0x00c0) == 0x0080) {
        return true;
    }
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        return is_disallowed_ipv4(
            std::net::Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                segments[6] as u8,
                (segments[7] >> 8) as u8,
                segments[7] as u8,
            ),
            reject_loopback,
        );
    }
    false
}

fn extract_dimensions(body: &serde_json::Value) -> Option<usize> {
    let data = body.get("data")?.as_array()?;
    let first = data.first()?;
    let embedding = first.get("embedding")?.as_array()?;
    if embedding.is_empty() {
        return None;
    }
    // Defensive: first entry must parse as a finite number.
    let sample = embedding.first()?.as_f64()?;
    if !sample.is_finite() {
        return None;
    }
    Some(embedding.len())
}

/// Walk a reqwest error's source chain so the user sees the underlying
/// cause (`connection refused`, `dns error: failed to lookup ...`,
/// `tls handshake eof`) instead of only the top-level `error sending
/// request for url (...)` message. Limited to 5 levels of depth as a
/// safety bound — reqwest errors typically only carry 1–2 sources.
fn format_error_with_causes(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut current = err.source();
    let mut depth = 0;
    while let Some(cause) = current {
        if depth >= 5 {
            break;
        }
        let cause_str = cause.to_string();
        // Skip empty causes and de-duplicate against the immediately
        // preceding part — reqwest occasionally wraps the same message
        // at multiple layers and we'd rather not surface it twice.
        if !cause_str.is_empty() && parts.last().map(|p| p.as_str()) != Some(cause_str.as_str()) {
            parts.push(cause_str);
        }
        current = cause.source();
        depth += 1;
    }
    parts.join(": ")
}

fn truncate_preview(text: &str) -> String {
    // Char-safe truncation so multi-byte bodies don't panic.
    let mut buf = String::with_capacity(MAX_PREVIEW_CHARS.min(text.len()));
    for (i, ch) in text.chars().enumerate() {
        if i >= MAX_PREVIEW_CHARS {
            buf.push('…');
            return buf;
        }
        buf.push(ch);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn substitute_leaves_text_without_tokens_untouched() {
        let (out, residual) = substitute_value("plain value", None);
        assert_eq!(out, "plain value");
        assert!(residual.is_none());
    }

    #[test]
    fn substitute_resolves_env_tokens() {
        std::env::set_var("MC_TEST_SUBST_KEY", "resolved-value");
        let (out, residual) = substitute_value("prefix-{env:MC_TEST_SUBST_KEY}-suffix", None);
        assert_eq!(out, "prefix-resolved-value-suffix");
        assert!(residual.is_none());
        std::env::remove_var("MC_TEST_SUBST_KEY");
    }

    #[test]
    fn substitute_reports_unresolved_env_tokens() {
        std::env::remove_var("MC_TEST_NONEXISTENT_VAR_FOR_PROBE");
        let (out, residual) = substitute_value("{env:MC_TEST_NONEXISTENT_VAR_FOR_PROBE}", None);
        // Unresolved token is preserved so the caller can detect it; the
        // probe will then surface it as UnresolvedToken.
        assert_eq!(out, "{env:MC_TEST_NONEXISTENT_VAR_FOR_PROBE}");
        assert_eq!(
            residual.as_deref(),
            Some("{env:MC_TEST_NONEXISTENT_VAR_FOR_PROBE}")
        );
    }

    #[test]
    fn substitute_trims_env_var_name_whitespace() {
        std::env::set_var("MC_TEST_SUBST_TRIM", "trimmed");
        let (out, residual) = substitute_value("{env: MC_TEST_SUBST_TRIM }", None);
        assert_eq!(out, "trimmed");
        assert!(residual.is_none());
        std::env::remove_var("MC_TEST_SUBST_TRIM");
    }

    #[test]
    fn substitute_handles_empty_env_value_as_unresolved() {
        std::env::set_var("MC_TEST_EMPTY_VAR", "");
        let (out, residual) = substitute_value("{env:MC_TEST_EMPTY_VAR}", None);
        assert_eq!(out, "{env:MC_TEST_EMPTY_VAR}");
        assert!(residual.is_some());
        std::env::remove_var("MC_TEST_EMPTY_VAR");
    }

    #[test]
    fn substitute_resolves_file_tokens_absolute() {
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join("mc-embedding-probe-test.txt");
        std::fs::write(&tmp_path, "file-contents-here").unwrap();
        let raw = format!("{{file:{}}}", tmp_path.display());
        let (out, residual) = substitute_value(&raw, None);
        assert_eq!(out, "file-contents-here");
        assert!(residual.is_none());
        std::fs::remove_file(&tmp_path).ok();
    }

    #[test]
    fn substitute_trims_file_contents() {
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join("mc-embedding-probe-trim-test.txt");
        std::fs::write(&tmp_path, "  whitespace-wrapped  \n").unwrap();
        let raw = format!("{{file:{}}}", tmp_path.display());
        let (out, _) = substitute_value(&raw, None);
        assert_eq!(out, "whitespace-wrapped");
        std::fs::remove_file(&tmp_path).ok();
    }

    #[test]
    fn substitute_reports_missing_files() {
        let (out, residual) = substitute_value("{file:/no/such/file/path.txt}", None);
        assert_eq!(out, "{file:/no/such/file/path.txt}");
        assert_eq!(residual.as_deref(), Some("{file:/no/such/file/path.txt}"));
    }

    #[test]
    fn substitute_handles_multiple_tokens_preserving_order() {
        std::env::set_var("MC_TEST_TOK_A", "A");
        std::env::set_var("MC_TEST_TOK_B", "B");
        let (out, residual) = substitute_value(
            "start-{env:MC_TEST_TOK_A}-mid-{env:MC_TEST_TOK_B}-end",
            None,
        );
        assert_eq!(out, "start-A-mid-B-end");
        assert!(residual.is_none());
        std::env::remove_var("MC_TEST_TOK_A");
        std::env::remove_var("MC_TEST_TOK_B");
    }

    #[test]
    fn extract_dimensions_accepts_valid_embedding() {
        let body = serde_json::json!({
            "data": [
                {
                    "embedding": [0.1, 0.2, 0.3, 0.4, 0.5]
                }
            ]
        });
        assert_eq!(extract_dimensions(&body), Some(5));
    }

    #[test]
    fn extract_dimensions_rejects_chat_style_body() {
        // OpenRouter would return something like this — 200 OK but not an
        // embeddings response. We classify as endpoint_unsupported.
        let body = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hello"}
            }]
        });
        assert!(extract_dimensions(&body).is_none());
    }

    #[test]
    fn extract_dimensions_rejects_empty_array() {
        let body = serde_json::json!({"data": []});
        assert!(extract_dimensions(&body).is_none());
    }

    #[test]
    fn extract_dimensions_rejects_non_numeric_embedding() {
        let body = serde_json::json!({
            "data": [{"embedding": ["not", "a", "number"]}]
        });
        assert!(extract_dimensions(&body).is_none());
    }

    #[test]
    fn truncate_preview_caps_long_bodies() {
        let long_input = "a".repeat(500);
        let preview = truncate_preview(&long_input);
        assert!(preview.ends_with('…'));
        // MAX_PREVIEW_CHARS chars followed by the ellipsis.
        assert_eq!(preview.chars().count(), MAX_PREVIEW_CHARS + 1);
    }

    #[test]
    fn truncate_preview_leaves_short_bodies_intact() {
        let preview = truncate_preview("short");
        assert_eq!(preview, "short");
    }

    // ── format_error_with_causes ──────────────────────────────

    use std::error::Error;
    use std::fmt;

    /// Tiny error with a manually-controlled source chain so we can verify
    /// the formatter walks it correctly without needing reqwest internals.
    #[derive(Debug)]
    struct ChainErr {
        msg: &'static str,
        source: Option<Box<ChainErr>>,
    }
    impl fmt::Display for ChainErr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.msg)
        }
    }
    impl Error for ChainErr {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source.as_deref().map(|e| e as &(dyn Error + 'static))
        }
    }

    #[test]
    fn format_error_with_causes_joins_chain() {
        let inner = ChainErr {
            msg: "Connection refused (os error 61)",
            source: None,
        };
        let outer = ChainErr {
            msg: "error sending request for url (http://localhost:1234)",
            source: Some(Box::new(inner)),
        };
        let formatted = format_error_with_causes(&outer);
        assert_eq!(
            formatted,
            "error sending request for url (http://localhost:1234): Connection refused (os error 61)"
        );
    }

    #[test]
    fn format_error_with_causes_handles_single_level() {
        let only = ChainErr {
            msg: "standalone failure",
            source: None,
        };
        assert_eq!(format_error_with_causes(&only), "standalone failure");
    }

    #[test]
    fn format_error_with_causes_dedups_repeated_messages() {
        let inner = ChainErr {
            msg: "same message",
            source: None,
        };
        let outer = ChainErr {
            msg: "same message",
            source: Some(Box::new(inner)),
        };
        assert_eq!(format_error_with_causes(&outer), "same message");
    }

    #[tokio::test]
    async fn probe_detects_invalid_scheme() {
        let outcome = probe_embedding_endpoint(EmbeddingProbeOptions {
            endpoint: "example.com/v1".to_string(),
            model: "text-embedding-3-small".to_string(),
            api_key: None,
            input_type: None,
            truncate: None,
            timeout_ms: 1000,
        })
        .await;
        assert!(matches!(
            outcome,
            EmbeddingProbeOutcome::InvalidScheme { .. }
        ));
    }

    #[tokio::test]
    async fn probe_detects_empty_endpoint() {
        let outcome = probe_embedding_endpoint(EmbeddingProbeOptions {
            endpoint: "".to_string(),
            model: "text-embedding-3-small".to_string(),
            api_key: None,
            input_type: None,
            truncate: None,
            timeout_ms: 1000,
        })
        .await;
        assert!(matches!(
            outcome,
            EmbeddingProbeOutcome::InvalidScheme { .. }
        ));
    }

    #[tokio::test]
    async fn browser_probe_times_out_with_bounded_timeout() {
        let (addr, handle) = spawn_test_server(Router::new().route(
            "/v1/embeddings",
            post(|| async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Json(serde_json::json!({ "data": [{ "embedding": [0.1, 0.2] }] }))
            }),
        ))
        .await;

        let outcome = probe_embedding_endpoint_browser(EmbeddingProbeOptions {
            endpoint: format!("http://127.0.0.1:{}/v1", addr.port()),
            model: "timeout-model".to_string(),
            api_key: None,
            input_type: None,
            truncate: None,
            timeout_ms: 25,
        })
        .await;

        assert!(matches!(
            outcome,
            EmbeddingProbeOutcome::Timeout { timeout_ms: 25 }
        ));
        handle.abort();
    }

    #[tokio::test]
    async fn browser_probe_stops_chunked_response_after_size_cap() {
        let hit_count = Arc::new(AtomicUsize::new(0));
        let hit_count_clone = hit_count.clone();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind raw server");
        let addr = listener.local_addr().expect("raw server addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            hit_count_clone.fetch_add(1, Ordering::SeqCst);
            let headers = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
            socket.write_all(headers).await.expect("write headers");
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..10 {
                socket
                    .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                    .await
                    .expect("write chunk size");
                socket.write_all(&chunk).await.expect("write chunk body");
                socket.write_all(b"\r\n").await.expect("write chunk tail");
            }
            socket.write_all(b"0\r\n\r\n").await.expect("write eof");
        });

        let outcome = probe_embedding_endpoint_browser(EmbeddingProbeOptions {
            endpoint: format!("http://127.0.0.1:{}/v1", addr.port()),
            model: "chunked-model".to_string(),
            api_key: None,
            input_type: None,
            truncate: None,
            timeout_ms: 2_000,
        })
        .await;

        match outcome {
            EmbeddingProbeOutcome::EndpointUnsupported { preview, .. } => {
                assert_eq!(preview, "response too large");
            }
            other => panic!("expected oversized endpoint_unsupported, got {other:?}"),
        }
        assert_eq!(hit_count.load(Ordering::SeqCst), 1);
        handle.abort();
    }

    #[tokio::test]
    async fn browser_probe_client_uses_pinned_dns_override_addrs() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let (addr, handle) = spawn_test_server(Router::new().route(
            "/v1/embeddings",
            post(move || {
                let hits = hits_clone.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({ "data": [{ "embedding": [0.1, 0.2] }] }))
                }
            }),
        ))
        .await;

        let validated = ValidatedBrowserEndpoint {
            embeddings_url: "http://does-not-resolve.invalid/v1/embeddings".to_string(),
            resolve_domain: Some("does-not-resolve.invalid".to_string()),
            resolved_addrs: vec![SocketAddr::from(([127, 0, 0, 1], addr.port()))],
        };
        let client = build_browser_probe_client(&validated, 1_000).expect("client");

        let response = client
            .post(&validated.embeddings_url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "model": "m", "input": "magic-context probe" }))
            .send()
            .await
            .expect("pinned request");

        assert!(response.status().is_success());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        handle.abort();
    }

    #[tokio::test]
    async fn validate_browser_endpoint_allows_exact_localhost_dns_loopback_resolution() {
        let validated = validate_browser_endpoint("http://localhost:11434/v1")
            .await
            .expect("localhost endpoint should validate");

        assert_eq!(validated.resolve_domain.as_deref(), Some("localhost"));
        assert!(
            !validated.resolved_addrs.is_empty(),
            "localhost should resolve to at least one socket addr"
        );
        assert!(validated
            .resolved_addrs
            .iter()
            .all(|addr| addr.ip().is_loopback()));
    }

    #[test]
    fn browser_probe_post_env_validation_rejects_resolved_file_tokens_and_caps() {
        std::env::set_var(
            "MC_TEST_EMBED_ENDPOINT_LONG",
            format!("https://example.com/{}", "x".repeat(2048)),
        );
        std::env::set_var("MC_TEST_EMBED_MODEL_LONG", "x".repeat(513));
        std::env::set_var("MC_TEST_EMBED_KEY_LONG", "k".repeat(8193));
        std::env::set_var("MC_TEST_EMBED_KEY_CTRL", "abc\ndef");
        std::env::set_var("MC_TEST_EMBED_FILE_TOKEN", "{file:/very/secret/path}");

        let endpoint_err = prepare_browser_probe_options(EmbeddingProbeOptions {
            endpoint: "{env:MC_TEST_EMBED_ENDPOINT_LONG}".to_string(),
            model: "ok".to_string(),
            api_key: None,
            input_type: None,
            truncate: None,
            timeout_ms: 100,
        })
        .expect_err("endpoint overflow should fail");
        assert!(
            matches!(endpoint_err, EmbeddingProbeOutcome::InvalidConfigField { ref field, .. } if field == "endpoint")
        );

        let model_err = prepare_browser_probe_options(EmbeddingProbeOptions {
            endpoint: "https://example.com/v1".to_string(),
            model: "{env:MC_TEST_EMBED_MODEL_LONG}".to_string(),
            api_key: None,
            input_type: None,
            truncate: None,
            timeout_ms: 100,
        })
        .expect_err("model overflow should fail");
        assert!(
            matches!(model_err, EmbeddingProbeOutcome::InvalidConfigField { ref field, .. } if field == "model")
        );

        let api_key_err = prepare_browser_probe_options(EmbeddingProbeOptions {
            endpoint: "https://example.com/v1".to_string(),
            model: "ok".to_string(),
            api_key: Some("{env:MC_TEST_EMBED_KEY_LONG}".to_string()),
            input_type: None,
            truncate: None,
            timeout_ms: 100,
        })
        .expect_err("api key overflow should fail");
        assert!(
            matches!(api_key_err, EmbeddingProbeOutcome::InvalidConfigField { ref field, .. } if field == "apiKey")
        );

        let api_key_ctrl_err = prepare_browser_probe_options(EmbeddingProbeOptions {
            endpoint: "https://example.com/v1".to_string(),
            model: "ok".to_string(),
            api_key: Some("{env:MC_TEST_EMBED_KEY_CTRL}".to_string()),
            input_type: None,
            truncate: None,
            timeout_ms: 100,
        })
        .expect_err("api key control chars should fail");
        assert!(
            matches!(api_key_ctrl_err, EmbeddingProbeOutcome::InvalidConfigField { ref field, ref message } if field == "apiKey" && message.contains("control characters"))
        );

        let file_token_err = prepare_browser_probe_options(EmbeddingProbeOptions {
            endpoint: "https://example.com/v1".to_string(),
            model: "ok".to_string(),
            api_key: Some("{env:MC_TEST_EMBED_FILE_TOKEN}".to_string()),
            input_type: None,
            truncate: None,
            timeout_ms: 100,
        })
        .expect_err("resolved file token should fail");
        match file_token_err {
            EmbeddingProbeOutcome::InvalidConfigField { field, message } => {
                assert_eq!(field, "apiKey");
                assert_eq!(message, "contains unsupported {file:...} token");
            }
            other => panic!("expected invalid config field, got {other:?}"),
        }

        for key in [
            "MC_TEST_EMBED_ENDPOINT_LONG",
            "MC_TEST_EMBED_MODEL_LONG",
            "MC_TEST_EMBED_KEY_LONG",
            "MC_TEST_EMBED_KEY_CTRL",
            "MC_TEST_EMBED_FILE_TOKEN",
        ] {
            std::env::remove_var(key);
        }
    }

    async fn spawn_test_server(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("server addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, handle)
    }
}
