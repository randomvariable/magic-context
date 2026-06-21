# Magic Context Dashboard

Magic Context dashboard supports two local runtimes:

- **Tauri desktop app** — packaged desktop shell
- **Localhost webserver** — Rust API/static server on `127.0.0.1`, browser UI from built `dist/`

The desktop app is the full-featured runtime. Localhost webserver mode is an
incremental browser runtime: it serves the dashboard UI locally and exposes the
HTTP API surface implemented so far.

## Features

- **Memory Browser** — Browse, search, edit, and manage cross-session memories
- **Session History Viewer** — Inspect compartments, facts, notes, and session metadata
- **Cache Diagnostics** — Real-time cache hit timeline with bust cause analysis
- **Dreamer Management** — Monitor and trigger dream tasks
- **Configuration Editor** — Visual editor for `magic-context.jsonc`
- **Log Viewer** — Real-time log tail with filtering and cache hit indicators

## Runtime coverage

**Desktop app:** full dashboard feature set.

**Localhost webserver:** currently supports the implemented `/api/*` surface:

- DB health and project list
- Memory Browser reads and memory CRUD actions
- Core session list/detail routes

Some dashboard areas still rely on Tauri IPC and remain desktop-only until later
API phases, including config editing/probing, dreamer management, logs/cache
detail, user-memory management, session messages, subagent detail, and some
session subviews. In browser mode those areas may be hidden, degraded, or fail
until their APIs are migrated.

## Prerequisites

- [Rust](https://rustup.rs/) (1.77+)
- [Bun](https://bun.sh/) or Node.js
- The [Magic Context plugin](https://github.com/cortexkit/magic-context) must be installed and have been run at least once (to create the SQLite database)

## Development

```bash
cd packages/dashboard

# Install frontend dependencies
bun install

# Desktop development mode (hot-reload frontend + Rust backend)
cargo tauri dev

# Desktop production build
cargo tauri build
```

## Localhost webserver mode

### Security model

Localhost mode is for **same-machine use only**.

- Server binds `127.0.0.1:1422` by default
- Browser assets are served locally from built dashboard `dist/`
- API stays under `POST /api/{command}`
- API requests still enforce local `Host` / `Origin` checks
- Protected, sensitive, and mutating API calls require `X-Magic-Context-Token`
- Legacy `X-Magic-Context-Local: 1` no longer authorizes protected commands
- No permissive CORS is added for LAN/Internet use

Do **not** expose this server to LAN, reverse proxy, or public Internet.

### Production-like localhost usage

Build frontend first, then start Rust webserver:

```bash
cd packages/dashboard

bun run build
bun run server:web
```

Or one command:

```bash
bun run serve:web
```

To build both the frontend and webserver binary before launching:

```bash
bun run serve:web:all
```

Then open:

```text
http://127.0.0.1:1422
```

If `dist/` is missing, server returns a clear build-missing page instead of panicking.

### Dev mode with Vite proxy

Run Rust localhost API server plus Vite dev server:

```bash
cd packages/dashboard

bun run dev:web
```

This starts:

- Rust localhost server on `127.0.0.1:1422`
- Vite frontend dev server on `127.0.0.1:1420`

`dev:web` now generates one random local token and passes it to both the Rust
server and Vite frontend automatically. You do not need to set matching token
env vars by hand.

Vite proxies `/api` to Rust server in dev mode.

If you want split terminals instead:

```bash
# use one shared token for both terminals
TOKEN=$(bun -e "console.log(crypto.randomUUID())")

# terminal 1
MAGIC_CONTEXT_DASHBOARD_TOKEN=$TOKEN bun run server:web

# terminal 2
VITE_MAGIC_CONTEXT_DASHBOARD_TOKEN=$TOKEN bun run dev:frontend
```

## Architecture

```
packages/dashboard/
├── src/                    # SolidJS frontend
│   ├── components/         # UI components per feature
│   │   ├── MemoryBrowser/  # Memory CRUD + search
│   │   ├── SessionViewer/  # Compartments, facts, notes
│   │   ├── CacheDiagnostics/ # Cache hit timeline + bust analysis
│   │   ├── DreamerPanel/   # Dream queue + state
│   │   ├── ConfigEditor/   # JSONC config editor
│   │   ├── LogViewer/      # Real-time log tail
│   │   └── Layout/         # App shell, nav, status bar
│   ├── lib/
│   │   ├── api.ts          # Browser/Tauri backend transport wrappers
│   │   └── types.ts        # TypeScript types matching Rust structs
│   ├── App.tsx             # Root component with navigation
│   ├── index.tsx           # Entry point
│   └── styles.css          # Global styles + design tokens
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── main.rs         # Tauri app setup + command registration
│   │   ├── lib.rs          # Shared state
│   │   ├── commands.rs     # Tauri command handlers
│   │   ├── services.rs     # Shared service layer for Tauri + localhost server
│   │   ├── webserver.rs    # Localhost API + static asset server
│   │   ├── db.rs           # SQLite reader + writer
│   │   ├── config.rs       # Config file reader + writer
│   │   └── log_parser.rs   # Log file parser + cache event extraction
│   ├── src/bin/
│   │   └── webserver.rs    # Headless localhost webserver entrypoint
│   ├── Cargo.toml
│   └── tauri.conf.json
├── index.html
├── vite.config.ts
└── package.json
```

## Data Sources

The dashboard reads from the same SQLite database the plugin writes to:
- **Database**: `~/.local/share/opencode/storage/plugin/magic-context/context.db`
- **Config**: `~/.config/opencode/magic-context.jsonc`
- **Logs**: `/tmp/magic-context.log`

Database access uses WAL mode for safe concurrent reads while the plugin writes. Write operations (memory edits, dream queue entries) use `busy_timeout` to handle contention.

In localhost mode, static routes are served from `packages/dashboard/dist/`. Resolution prefers `MAGIC_CONTEXT_DASHBOARD_DIST` when set, then common relative locations such as:

- `packages/dashboard/dist`
- `src-tauri/../dist`
- repo-root `packages/dashboard/dist`

## Design

Dark-first developer tool following the wireframe spec in `.sisyphus/plans/magic-context-dashboard-wireframes.md`. Key design tokens:

| Token | Hex | Usage |
|-------|-----|-------|
| `bg-base` | `#0a0a0f` | App background |
| `bg-panel` | `#13131a` | Panel background |
| `bg-card` | `#1c1c27` | Card background |
| `accent` | `#3b82f6` | Primary actions |
| `green` | `#22c55e` | Healthy/success |
| `amber` | `#f59e0b` | Warning |
| `red` | `#ef4444` | Error/bust |
