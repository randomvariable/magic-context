export function isTauriRuntime(): boolean {
  if (typeof window === "undefined") return false;

  const candidate = window as typeof window & {
    __TAURI__?: unknown;
    __TAURI_INTERNALS__?: unknown;
  };

  return Boolean(candidate.__TAURI__ || candidate.__TAURI_INTERNALS__);
}
