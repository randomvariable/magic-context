import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const APP_SOURCE = readFileSync(resolve(import.meta.dir, "./App.tsx"), "utf-8");
const API_SOURCE = readFileSync(resolve(import.meta.dir, "./lib/api.ts"), "utf-8");
const CONFIG_EDITOR_SOURCE = readFileSync(
  resolve(import.meta.dir, "./components/ConfigEditor/ConfigEditor.tsx"),
  "utf-8",
);

describe("browser model discovery guards", () => {
  it("#given App mount refresh #then browser path is guarded behind isTauriRuntime", () => {
    expect(APP_SOURCE).toContain("if (!isTauriRuntime()) return;");
    expect(APP_SOURCE).toContain("void refreshModelDiscovery();");
  });

  it("#given model discovery wrappers #then browser uses localhost backend routes instead of desktop invoke", () => {
    expect(API_SOURCE).toContain('return callBackend("get_available_models")');
    expect(API_SOURCE).toContain('return callBackend("get_available_pi_models")');
    expect(API_SOURCE).toContain('return callBackend("test_embedding_endpoint"');
    expect(API_SOURCE).not.toContain('invokeTauri("get_available_models")');
    expect(API_SOURCE).not.toContain('invokeTauri("get_available_pi_models")');
    expect(API_SOURCE).not.toContain('invokeTauri("test_embedding_endpoint")');
  });

  it("#given config page #then model discovery requires explicit visible user action", () => {
    expect(CONFIG_EDITOR_SOURCE).toContain("↻ Refresh Models");
    expect(CONFIG_EDITOR_SOURCE).toContain("onRefreshModels");
  });

  it("#given config page embedding probe #then it remains explicit button-only with browser safety copy", () => {
    expect(CONFIG_EDITOR_SOURCE).toContain("⚡ Test Connection");
    expect(CONFIG_EDITOR_SOURCE).toContain("Sends one explicit test request");
    expect(CONFIG_EDITOR_SOURCE).toContain("embeddingTestInFlight");
    expect(CONFIG_EDITOR_SOURCE).not.toContain("onMount(() => testEmbeddingEndpoint(");
    expect(CONFIG_EDITOR_SOURCE).not.toContain("createEffect(() => testEmbeddingEndpoint(");
  });
});
