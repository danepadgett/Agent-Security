# Core Agent

The core agent is the Rust-based security engine for Agent-Security.

## Purpose

It monitors local system behavior, converts raw activity into telemetry, evaluates suspicious behavior, groups related events into incidents, and triggers automated response actions when policy thresholds are met.

## Responsibilities

- monitor file system activity
- detect newly launched processes
- classify suspicious behavior
- score and generate detections
- correlate detections into incidents
- respond automatically based on policy
- write structured logs

## Main Flow

1. Load response policy
2. Establish startup baseline
3. Watch monitored directories
4. Detect new process execution
5. Generate telemetry events
6. Evaluate detections
7. Aggregate incidents
8. Trigger response actions
9. Append structured logs

## Important Modules

- `main.rs` — main loop and orchestration
- `config.rs` — runtime policy
- `files.rs` — file event monitoring
- `processes.rs` — process discovery
- `detections.rs` — scoring and detection logic
- `execution_graph.rs` — event relationship tracking
- `incidents.rs` — incident creation and grouping
- `response.rs` — automated action execution
- `guardrails.rs` — safety controls
- `logging.rs` — structured output
- `models.rs` — shared types
- `state.rs` — runtime memory/state

## Run

```bash
cargo run