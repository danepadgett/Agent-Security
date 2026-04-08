# core-agent

The Rust EDR engine for Hound. Monitors macOS system activity, detects scope violations and attack patterns, correlates signals into incidents, and responds automatically.

## Run

```bash
cargo run --bin core-agent               # Run the agent (simulation mode by default)
cargo run --bin watchdog                 # Run the watchdog (respawns agent if it dies)
cargo run --bin core-agent -- --perf-report    # Print performance summary and exit
cargo run --bin core-agent -- --list-whitelist # Print current whitelist and exit
cargo run --bin core-agent -- --clear-baseline # Delete baseline.db and exit
cargo test                               # Run all 270 unit tests
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
execution_context.rs  Classify execution source: Terminal / IDE / CI / Script / Unknown
scope_violation.rs    Scope violation detection — credential access, unexpected network,
                      persistence, privilege escalation, download-and-execute

  ↓
detections.rs        Detection functions, evaluated per event
command_patterns.rs  LOLBin and pipe-to-shell detection
config_integrity.rs  SHA256 tamper detection on config + logs
lateral_movement.rs  Expanded SSH/sudo lateral movement and privilege escalation
exfiltration.rs      rclone, curl upload, cloud storage, sensitive directory archive
cryptomining.rs      Miner binary/args/pool connection detection
supply_chain.rs      Package postinstall download, typosquatting, CI config tampering

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

## Key signals and scores

| Signal | Score |
|---|---|
| alert_binary_integrity_violation | 40 |
| alert_cryptomining | 38 |
| alert_boot_security_tamper | 30 |
| alert_ransomware_behavior_detected | 30 |
| alert_security_tool_tampering | 28 |
| alert_process_injection (grouped) | 35 |
| alert_malicious_document (grouped) | 28 |
| alert_dylib_hijacking_attempt | 28 |
| alert_curl_pipe_bash | 22 |
| alert_defense_evasion_active | 22 |
| alert_hosts_file_tampered | 22 |
| alert_suspected_exfiltration | 24 |
| alert_connection_burst_detected | 24 |
| alert_keychain_dump_attempt | 25 |
| alert_lateral_movement_ext (grouped) | 28 |
| alert_exfiltration_ext (grouped) | 26 |
| alert_ssh_lateral_movement | 20 |
| alert_recon_correlation (grouped) | 20 |
| alert_obfuscated_content_detected | 20 |
| alert_keychain_access_attempt | 18 |
| alert_browser_credential_access | 18 |
| alert_data_staging_detected | 18 |
| tight_time_window_bonus (all signals within 30s) | +8 |
| repeat_offender_pid_bonus | +8 to +12 |

## Modules

| File | Purpose |
|---|---|
| `main.rs` | Entry point, main loop, CLI flag handling |
| `execution_context.rs` | ExecutionSource classification, ExecutionContext, ExecutionTracker |
| `scope_violation.rs` | Developer-focused scope violation detection |
| `config.rs` | Config loading, whitelist, hot-reload primitives |
| `detections.rs` | All detection functions + evaluation loop |
| `incidents.rs` | Attack chain correlation and incident scoring |
| `response.rs` | Response actions with guardrails and audit log |
| `files.rs` | File event monitoring, magic bytes detection |
| `processes.rs` | Process enumeration and classification |
| `network.rs` | Network telemetry, C2 beaconing patterns |
| `persistence_monitor.rs` | LaunchAgent, crontab, BTM monitoring |
| `command_patterns.rs` | LOLBin and injection pattern matching |
| `lateral_movement.rs` | SSH/sudo lateral movement, privilege escalation |
| `exfiltration.rs` | Cloud upload, rclone, sensitive directory archive |
| `cryptomining.rs` | Miner binary/args/pool detection |
| `supply_chain.rs` | Package postinstall, typosquatting, CI tampering |
| `config_integrity.rs` | Config and log tamper detection |
| `entropy.rs` | Shannon entropy + obfuscation analysis (T1027) |
| `binary_integrity.rs` | Binary hash baseline + supply chain detection |
| `dns_monitor.rs` | /etc/hosts tamper + DGA analysis |
| `filesystem_anomaly.rs` | Ransomware wave, ransom note, mass modification |
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
│   ├── hound_traces.jsonl      Permanent Hound Trace history
│   ├── perf-stats.jsonl        Per-subsystem performance metrics
│   └── watchdog.log            Watchdog restart events
├── quarantine/                 Quarantined files + SHA256 manifest
└── incidents/                  JSON evidence packs per incident
```
