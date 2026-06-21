import { ask, message } from "./dialog";
import { isTauriRuntime } from "./runtime";

type CachedUpdate = {
  version: string;
  download: () => Promise<void>;
  install: () => Promise<void>;
};

let cachedUpdate: CachedUpdate | null = null;

/**
 * Check if an update is available. Returns the version string if found, null otherwise.
 * Used by the background polling in App.tsx for the toast notification.
 */
export async function checkForUpdate(): Promise<string | null> {
  if (!isTauriRuntime()) return null;

  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = await check();
    if (update) {
      cachedUpdate = update;
      return update.version;
    }
  } catch {
    // Silent failure for background checks
  }
  return null;
}

/**
 * Download and install the cached update, then relaunch.
 * Called when user clicks "Install & Restart" in the toast.
 */
export async function installAndRelaunch(): Promise<void> {
  if (!isTauriRuntime() || !cachedUpdate) return;
  try {
    const { relaunch } = await import("@tauri-apps/plugin-process");
    await cachedUpdate.download();
    await cachedUpdate.install();
    await relaunch();
  } catch {
    // If install fails, user stays on current version
  }
}

/**
 * Run a full interactive update check with dialogs.
 * Called from "Check for Updates..." tray menu item.
 * Following OpenCode's pattern: check → download → ask → install → relaunch.
 */
export async function runUpdater({ alertOnFail }: { alertOnFail: boolean }) {
  if (!isTauriRuntime()) return;

  let update: CachedUpdate | null;
  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    update = await check();
  } catch {
    if (alertOnFail) {
      await message("Failed to check for updates", { title: "Update Check Failed" });
    }
    return;
  }

  if (!update) {
    if (alertOnFail) {
      await message("You are already using the latest version of Magic Context Dashboard", {
        title: "No Update Available",
      });
    }
    return;
  }

  try {
    await update.download();
  } catch {
    if (alertOnFail) {
      await message("Failed to download update", { title: "Update Failed" });
    }
    return;
  }

  const shouldUpdate = await ask(
    `Magic Context Dashboard ${update.version} has been downloaded. Would you like to install and restart?`,
    { title: "Update Downloaded" },
  );
  if (!shouldUpdate) return;

  try {
    await update.install();
  } catch {
    await message("Failed to install update", { title: "Update Failed" });
    return;
  }

  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
