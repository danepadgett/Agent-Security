# Repository Map

## Root

### `README.md`
Top-level overview of the platform, current capabilities, architecture, setup, and long-term vision.

### `docs/`
Project documentation for architecture, detection logic, response behavior, and roadmap.

### `runtime/`
Runtime-generated data such as logs and future quarantine or incident artifacts.

---

## `agents/core-agent/`

### Purpose
The Rust-based endpoint detection and response engine.

### Key Files

#### `Cargo.toml`
Rust crate manifest and dependencies for the core agent.

#### `src/main.rs`
Application entry point. Starts the monitoring loop, loads policy, collects telemetry, evaluates detections, aggregates incidents, and triggers responses.

#### `src/config.rs`
Loads runtime policy and default settings.

#### `src/files.rs`
Handles file monitoring and file-event collection.

#### `src/processes.rs`
Detects newly launched processes and snapshots process state.

#### `src/detections.rs`
Applies rules and scoring to telemetry to create detections.

#### `src/execution_graph.rs`
Tracks relationships between events, files, and processes.

#### `src/incidents.rs`
Groups related detections into incidents.

#### `src/response.rs`
Carries out automated response actions such as kill or quarantine.

#### `src/guardrails.rs`
Prevents overly aggressive or unsafe response behavior.

#### `src/logging.rs`
Writes structured logs and telemetry output.

#### `src/models.rs`
Defines shared structs and event models used across modules.

#### `src/state.rs`
Stores runtime state shared across the agent.

---

## `apps/desktop/`

### Purpose
User-facing desktop application for alerts, incidents, and system visibility.

### Key Files

#### `package.json`
Frontend package manifest and scripts.

#### `src/`
React frontend source code.

#### `src-tauri/`
Tauri backend code for the desktop application.

#### `vite.config.ts`
Frontend build configuration.

---

## `runtime/logs/`

### `agent-events.jsonl`
Structured runtime event log produced by the core agent.