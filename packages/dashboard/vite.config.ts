import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import { resolve } from "node:path";

const host = process.env.TAURI_DEV_HOST;
const apiPort = process.env.MAGIC_CONTEXT_DASHBOARD_PORT || "1422";

export default defineConfig(async () => ({
  plugins: [solidPlugin()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "./src"),
    },
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    proxy: host
      ? undefined
      : {
          "/api": {
            target: `http://127.0.0.1:${apiPort}`,
            changeOrigin: false,
          },
        },
  },
}));
