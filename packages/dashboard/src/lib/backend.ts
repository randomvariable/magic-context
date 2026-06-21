import { isTauriRuntime } from "./runtime";

const BOOTSTRAP_SCRIPT_ID = "magic-context-bootstrap";

type BootstrapPayload = {
  localToken?: string;
};

type BackendOkEnvelope<T> = {
  ok: true;
  data: T;
};

type BackendErrorEnvelope = {
  ok: false;
  error?: unknown;
};

function formatBackendError(error: unknown, fallback: string): string {
  if (typeof error === "string" && error.trim()) return error;
  if (error && typeof error === "object") {
    const message = "message" in error ? error.message : undefined;
    if (typeof message === "string" && message.trim()) return message;
  }
  return fallback;
}

export function getLocalToken(): string | undefined {
  if (typeof document !== "undefined") {
    const bootstrap = document.getElementById(BOOTSTRAP_SCRIPT_ID);
    const raw = bootstrap?.textContent?.trim();
    if (raw) {
      try {
        const payload = JSON.parse(raw) as BootstrapPayload;
        if (typeof payload.localToken === "string" && payload.localToken.trim()) {
          return payload.localToken;
        }
      } catch {
        // Ignore malformed bootstrap payload and fall through to env.
      }
    }
  }

  const envToken = import.meta.env.VITE_MAGIC_CONTEXT_DASHBOARD_TOKEN;
  return typeof envToken === "string" && envToken.trim() ? envToken : undefined;
}

export async function callBackend<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (isTauriRuntime()) {
    return invokeTauri<T>(command, args);
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  const localToken = getLocalToken();
  if (localToken) {
    headers["X-Magic-Context-Token"] = localToken;
  }

  const response = await fetch(`/api/${encodeURIComponent(command)}`, {
    method: "POST",
    headers,
    body: JSON.stringify(args ?? {}),
  });

  let payload: BackendOkEnvelope<T> | BackendErrorEnvelope | undefined;
  try {
    payload = (await response.json()) as BackendOkEnvelope<T> | BackendErrorEnvelope;
  } catch {
    throw new Error(`Backend ${command} returned invalid JSON (${response.status})`);
  }

  if (!payload || typeof payload !== "object" || !("ok" in payload)) {
    throw new Error(`Backend ${command} returned malformed response`);
  }

  if (!response.ok) {
    throw new Error(
      formatBackendError(payload.ok ? undefined : payload.error, `Backend ${command} failed (${response.status})`),
    );
  }

  if (!payload.ok) {
    throw new Error(formatBackendError(payload.error, `Backend ${command} failed`));
  }

  return payload.data;
}

export async function invokeTauri<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauriRuntime()) {
    throw new Error(
      `${command} is only available in the desktop app; this browser server has not exposed that API yet.`,
    );
  }

  const { invoke } = await import("@tauri-apps/api/core");
  if (typeof invoke !== "function") {
    throw new Error(`Tauri invoke API is unavailable for ${command}`);
  }

  return invoke<T>(command, args);
}
