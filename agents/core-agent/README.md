# core-agent

The Rust EDR engine for Hound. Monitors macOS system activity, detects attack patterns, correlates signals into incidents, and responds automatically.

## Run

```bash
cargo run --bin core-agent               # Run the agent (simulation mode by default)
cargo run --bin watchdog                 # Run the watchdog (respawns agent if it dies)
cargo run --bin core-agent -- --perf-report    # Print performance summary and exit
cargo run --bin core-agent -- --list-whitelist # Print current whitelist and exit
cargo run --bin core-agent -- --clear-baseline # Delete baseline.db and exit
cargo test                               # Run all 165 unit tests
```

## Configuration

Agent reads `runtime/agent-config.toml` at startup and hot-reloads it every tick for:
- `simulation_mode` — if true, detects but takes no action (default: true)
- `incident_threshold` — minimum score to emit a behavioral incident (default: 35)
- `[detection_whitelist]` — processes/paths that generate zero alerts
- `[whitelist]` — trusted processes that won't be killed/quarantined (but still alerted)

The agent **defaults to simulation_mode=true on any config read error**. This is load-bearing safety behavior.

## Architecture

```
main.rs              Main loop, orchestration, CLI flags
  ↓
Sensor layer
  files.rs           inotify-style polling of watched directories
  processes.rs       sysinfo-based process enumeration (reuses System object across ticks)
  network.rs         lsof polling for connections, C2 beaconing detection
  persistence_monitor.rs  LaunchAgents, crontab, BTM database

  ↓
detections.rs        45 detection functions, evaluated per event
command_patterns.rs  LOLBin and pipe-to-shell detection
config_integrity.rs  SHA256 tamper detection on config + logs

  ↓
incidents.rs         Correlation engine — groups signals into scored attack chains
baseline.rs          SQLite behavioral baseline — reduces false positives over time
lineage.rs           Process ancestry tracking
provenance.rs        File origin tracking

  ↓
response.rs          Guardrails → whitelist check → kill / quarantine / simulate
state.rs             Per-incident cooldown tracking, response audit
evidence.rs          JSON evidence packs per incident

  ↓
logging.rs           JSONL telemetry with log rotation (50MB / 5 files)
perf.rs              Per-subsystem timing, p95 tracking, CPU throttle
```

## Detection functions (45 total, 165 tests)

Organized by MITRE ATT&CK tactic. Every function has:
- a positive test case (detects the attack)
- a negative test case (does not false-positive on normal behavior)

Key signals and their scores in the incident correlator:

| Signal | Score |
|---|---|
| alert_boot_security_tamper | 30 |
| alert_ransomware_behavior_detected | 30 |
| alert_security_tool_tampering | 28 |
| alert_curl_pipe_bash | 22 |
| alert_suspected_exfiltration | 24 |
| alert_ssh_lateral_movement | 20 |
| alert_keychain_access_attempt | 18 |
| alert_browser_credential_access | 18 |
| alert_data_staging_detected | 18 |
| tight_time_window_bonus (all signals within 30s) | +8 |
| repeat_offender_pid_bonus | +8 to +12 |

## Modules

| File | Purpose |
|---|---|
| `main.rs` | Entry point, main loop, CLI flag handling |
| `config.rs` | Config loading, whitelist, hot-reload primitives |
| `detections.rs` | All 45 detection functions + evaluation loop |
| `incidents.rs` | Attack chain correlation and incident scoring |
| `response.rs` | Response actions with guardrails and audit log |
| `files.rs` | File event monitoring, magic bytes detection |
| `processes.rs` | Process enumeration and classification |
| `network.rs` | Network telemetry, C2 beaconing patterns |
| `persistence_monitor.rs` | LaunchAgent, crontab, BTM monitoring |
| `command_patterns.rs` | LOLBin and injection pattern matching |
| `config_integrity.rs` | Config and log tamper detection |
| `baseline.rs` | SQLite behavioral baseline |
| `lineage.rs` | Process ancestry cache |
| `provenance.rs` | File origin cache |
| `state.rs` | Incident state, cooldowns, response records |
| `evidence.rs` | JSON evidence pack writer |
| `logging.rs` | JSONL append, log rotation |
| `perf.rs` | Subsystem timing, p95, CPU throttle |
| `guardrails.rs` | Hard safety limits (never kill system processes) |
| `models.rs` | Shared types (TelemetryEvent, ProcessInfo, etc.) |
| `bin/watchdog.rs` | Standalone watchdog binary |

## Runtime files

All runtime data lives in `runtime/` (gitignored):

```
runtime/
├── agent-config.toml           Live configuration (hot-reloaded)
├── baseline.db                 SQLite behavioral baseline
├── logs/
│   ├── agent-events.jsonl      Primary telemetry (50MB, 5 rotated files)
│   ├── response-audit.jsonl    Every response action taken
│   ├── storylines.jsonl        Permanent StoryLine history
│   ├── perf-stats.jsonl        Per-subsystem performance metrics
│   └── watchdog.log            Watchdog restart events
├── quarantine/                 Quarantined files + SHA256 manifest
└── incidents/                  JSON evidence packs per incident
```
