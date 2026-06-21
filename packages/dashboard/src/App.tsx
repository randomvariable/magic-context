import { createResource, createSignal, ErrorBoundary, onCleanup, onMount, Show } from "solid-js";
import CacheDiagnostics from "./components/CacheDiagnostics/CacheDiagnostics";
import ConfigEditor from "./components/ConfigEditor/ConfigEditor";
import DreamerPanel from "./components/DreamerPanel/DreamerPanel";
import Sidebar from "./components/Layout/Sidebar";
import StatusBar from "./components/Layout/StatusBar";
import LogViewer from "./components/LogViewer/LogViewer";
import MemoryBrowser from "./components/MemoryBrowser/MemoryBrowser";
import SessionViewer from "./components/SessionViewer/SessionViewer";
import UserMemories from "./components/UserMemories/UserMemories";
import WorkspacesPanel from "./components/WorkspacesPanel/WorkspacesPanel";
import { getAvailableModels, getAvailablePiModels, getDbHealth } from "./lib/api";
import { isTauriRuntime } from "./lib/runtime";
import type { NavSection } from "./lib/types";
import { checkForUpdate, installAndRelaunch, runUpdater } from "./lib/updater";

const MODELS_CACHE_KEY = "mc_dashboard_models_cache";
const PI_MODELS_CACHE_KEY = "magic-context.available-pi-models";
const UPDATE_POLL_INTERVAL = 10 * 60 * 1000; // 10 minutes

function loadCachedModels(): string[] {
  try {
    const raw = localStorage.getItem(MODELS_CACHE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function loadCachedPiModels(): string[] {
  try {
    const raw = localStorage.getItem(PI_MODELS_CACHE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export default function App() {
  const [activeSection, setActiveSection] = createSignal<NavSection>("memories");
  const [health] = createResource(getDbHealth);
  const [availableModels, setAvailableModels] = createSignal<string[]>(loadCachedModels());
  const [availablePiModels, setAvailablePiModels] = createSignal<string[]>(loadCachedPiModels());
  const [modelsRefreshing, setModelsRefreshing] = createSignal(false);
  const [updateVersion, setUpdateVersion] = createSignal<string | null>(null);
  const [updateInstalling, setUpdateInstalling] = createSignal(false);
  const [updateDismissed, setUpdateDismissed] = createSignal(false);

  const refreshModelDiscovery = async () => {
    setModelsRefreshing(true);
    try {
      const [freshModels, freshPiModels] = await Promise.all([
        getAvailableModels().catch(() => availableModels()),
        getAvailablePiModels().catch(() => availablePiModels()),
      ]);
      setAvailableModels(freshModels);
      setAvailablePiModels(freshPiModels);
      try {
        localStorage.setItem(MODELS_CACHE_KEY, JSON.stringify(freshModels));
        localStorage.setItem(PI_MODELS_CACHE_KEY, JSON.stringify(freshPiModels));
      } catch {}
    } finally {
      setModelsRefreshing(false);
    }
  };

  // Background model refresh (desktop only)
  onMount(() => {
    if (!isTauriRuntime()) return;
    void refreshModelDiscovery();
  });

  // Background update polling
  let updateInterval: ReturnType<typeof setInterval> | undefined;
  onMount(() => {
    if (!isTauriRuntime()) return;

    const poll = () => {
      if (updateVersion()) return; // already found
      checkForUpdate().then((version) => {
        if (version) setUpdateVersion(version);
      });
    };
    // Check immediately, then every 10 minutes
    poll();
    updateInterval = setInterval(poll, UPDATE_POLL_INTERVAL);
  });
  onCleanup(() => {
    if (updateInterval) clearInterval(updateInterval);
  });

  // Listen for "Check for Updates" tray menu event
  let unlistenUpdate: (() => void) | undefined;
  onMount(() => {
    if (!isTauriRuntime()) return;

    import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen("check-for-updates", () => {
          runUpdater({ alertOnFail: true });
        }),
      )
      .then((unlisten) => {
        unlistenUpdate = unlisten;
      })
      .catch(() => {
        unlistenUpdate = undefined;
      });
  });
  onCleanup(() => {
    unlistenUpdate?.();
  });

  const handleInstall = async () => {
    setUpdateInstalling(true);
    await installAndRelaunch();
    // If relaunch fails, reset state
    setUpdateInstalling(false);
  };

  return (
    <div class="app-shell">
      <Sidebar active={activeSection()} onNavigate={setActiveSection} />

      <main class="content">
        {/* Update toast */}
        <Show when={updateVersion() && !updateDismissed()}>
          <div class="update-toast">
            <div class="update-toast-content">
              <span class="update-toast-icon">⬆</span>
              <div class="update-toast-text">
                <strong>Update available</strong>
                <span>v{updateVersion()} is ready to install</span>
              </div>
            </div>
            <div class="update-toast-actions">
              <button
                type="button"
                class="btn primary sm"
                disabled={updateInstalling()}
                onClick={handleInstall}
              >
                {updateInstalling() ? "Installing..." : "Install & Restart"}
              </button>
              <button type="button" class="btn sm" onClick={() => setUpdateDismissed(true)}>
                Later
              </button>
            </div>
          </div>
        </Show>

        <ErrorBoundary
          fallback={(err, reset) => (
            <div class="error-boundary">
              <h2>Something went wrong</h2>
              <p>{err?.message || "An unexpected error occurred"}</p>
              <button type="button" class="btn primary" onClick={reset}>
                Try Again
              </button>
            </div>
          )}
        >
          <Show when={activeSection() === "memories"}>
            <MemoryBrowser />
          </Show>
          <Show when={activeSection() === "sessions"}>
            <SessionViewer />
          </Show>
          <Show when={activeSection() === "cache"}>
            <CacheDiagnostics />
          </Show>
          <Show when={activeSection() === "workspaces"}>
            <WorkspacesPanel />
          </Show>
          <Show when={activeSection() === "dreamer"}>
            <DreamerPanel />
          </Show>
          <Show when={activeSection() === "user-memories"}>
            <UserMemories />
          </Show>
          <Show when={activeSection() === "config"}>
            <ConfigEditor
              models={availableModels()}
              piModels={availablePiModels()}
              onRefreshModels={refreshModelDiscovery}
              modelsRefreshing={modelsRefreshing()}
            />
          </Show>
          <Show when={activeSection() === "logs"}>
            <LogViewer />
          </Show>
        </ErrorBoundary>
      </main>

      <StatusBar health={health()} />
    </div>
  );
}
