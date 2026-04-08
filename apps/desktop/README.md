# Hound Desktop

Tauri + React desktop UI for Hound. Connects to the core-agent's JSONL log file and provides an incident inbox, health dashboard, history, and settings.

## Dev

```bash
npm install
npm run tauri dev
```

Requires the core-agent to be running (separate terminal):

```bash
cd ../../agents/core-agent && cargo run --bin core-agent
```

## Build

```bash
npm run tauri build
# App bundle: src-tauri/target/release/bundle/macos/Hound.app
```

## Environment

Copy `.env.example` to `.env` — Supabase is optional. Without it, auth is skippable and heartbeats are no-ops. All core detection and UI features work without Supabase.

```bash
cp .env.example .env
```

## Architecture

```
src/
├── App.tsx                 Main app, event subscription, incident state
├── components/
│   ├── Onboarding.tsx      5-screen first-run flow (permissions, privacy, health check)
│   ├── AuthScreen.tsx      Sign-up / sign-in / skip
│   ├── IncidentFeed.tsx    Inbox model with burst mode banner
│   ├── HoundTrace.tsx      Plain-English incident narrative + AI enhancement
│   ├── HistoryView.tsx     Complete incident history, searchable
│   ├── HealthDashboard.tsx Stats, severity chart, MITRE chart, sim mode toggle
│   ├── SettingsView.tsx    Whitelist editor, API key (Keychain), log path
│   ├── Sidebar.tsx         Nav with incident count badge
│   ├── TopBar.tsx          Protection status bar
│   └── DarkWebMonitor.tsx  HIBP breach monitoring
├── lib/
│   └── supabase.ts         Supabase client (gracefully degrades if not configured)
├── types.ts                Shared TypeScript types
└── utils.ts                JSON parsing, incident field extraction

src-tauri/src/lib.rs        All Tauri commands (file I/O, keychain, agent control)
```

## Tauri commands

| Command | Purpose |
|---|---|
| `read_agent_events` | Tail last 1MB of agent log, return as string array |
| `get_agent_status` | Check if core-agent is running via pgrep |
| `get_simulation_mode` | Read simulation_mode from config |
| `set_simulation_mode` | Write simulation_mode to config |
| `generate_hound_trace` | Build deterministic plain-English incident narrative |
| `acknowledge_with_hound_trace` | Acknowledge incident + generate + persist Hound Trace |
| `get_hound_traces` | Return all Hound Traces (newest first) |
| `explain_incident` | Call Claude Haiku API for AI-enhanced Hound Trace |
| `set_api_key` | Store Anthropic API key in macOS Keychain |
| `get_whitelist` | Read whitelist from config |
| `update_whitelist` | Write whitelist to config |
| `quarantine_file` | Move file to runtime/quarantine/ with SHA256 manifest |
| `is_first_run` | Check if first_run_complete in config |
| `complete_onboarding` | Write first_run_complete = true to config |
| `check_permissions` | Test Full Disk Access + Accessibility |
| `clear_false_positives` | Remove whitelisted processes from unacknowledged incidents |
| `check_email_breaches` | Query HIBP API v3 |
