import { isTauriRuntime } from "./runtime";

type DialogOptions = {
  title?: string;
  kind?: "info" | "warning" | "error";
  okLabel?: string;
  cancelLabel?: string;
};

export async function ask(message: string, options?: DialogOptions): Promise<boolean> {
  if (isTauriRuntime()) {
    const dialog = await import("@tauri-apps/plugin-dialog");
    return dialog.ask(message, options);
  }

  const title = options?.title?.trim();
  return window.confirm(title ? `${title}\n\n${message}` : message);
}

export async function message(text: string, options?: DialogOptions): Promise<void> {
  if (isTauriRuntime()) {
    const dialog = await import("@tauri-apps/plugin-dialog");
    await dialog.message(text, options);
    return;
  }

  const title = options?.title?.trim();
  window.alert(title ? `${title}\n\n${text}` : text);
}
