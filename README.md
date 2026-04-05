# Hound

Behavioral endpoint protection for macOS. Free, forever.

Hound is a local-first EDR (Endpoint Detection and Response) agent for macOS. It watches for attack patterns in real time, explains every incident in plain English, and responds automatically — or in simulation mode for safe testing. No cloud dependency for core detection. No subscription. No telemetry without consent.

---

## What it does

- **Behavioral detection** — 45 detection functions covering ~95% of MITRE ATT&CK user-space techniques. Catches attack patterns that signature-based tools miss.
- **Incident correlation** — Groups atomic signals into scored attack chains with MITRE technique tagging.
- **Automated response** — Kills malicious processes and quarantines files (simulation mode by default).
- **Plain-English explanations** — Every incident gets a deterministic StoryLine narrative. Optional AI enhancement via Claude Haiku (bring your own API key).
- **Desktop UI** — Tauri + React app with incident inbox, history, health dashboard, and settings.
- **Local-first** — Everything runs on your Mac. No cloud required for detection or response.

---

## Quick start

### Prerequisites

- macOS 13+ (tested on macOS 15)
- [Rust](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/) 18+ and npm
- Xcode Command Line Tools: `xcode-select --install`

### 1. Clone

```bash
git clone https://github.com/your-org/hound.git
cd hound
```

### 2. Run the agent

```bash
cd agents/core-agent
cargo run --bin core-agent
```

The agent starts in **simulation mode** by default — it detects and logs threats but takes no real action. You'll see output like:

```
Core Agent Starting...
[core-agent] project root: /path/to/hound
Watching directories:
 - /Users/you/Downloads
 - /Users/you/Desktop
 ...
Startup baseline established. Alerting enabled on next loop.
```

Telemetry is written to `runtime/logs/agent-events.jsonl`.

### 3. Run the desktop UI

In a separate terminal:

```bash
cd apps/desktop
npm install
npm run tauri dev
```

The UI connects to the agent's log file automatically. On first launch you'll see the onboarding flow — grant Full Disk Access when prompted for full coverage.

---

## Configuration

Runtime configuration lives in `runtime/agent-config.toml`. The agent hot-reloads this file — no restart required for most changes.

### Enable live response

```toml
simulation_mode = false
```

When live response is enabled, the agent will kill malicious processes and quarantine suspicious files. **Test in simulation mode first.**

### Adjust detection sensitivity

```toml
[policy]
incident_threshold = 35   # Minimum score to emit an alert_behavioral_incident
kill_threshold = 85       # Score needed to kill a process
quarantine_threshold = 75 # Score needed to quarantine a file
```

### Suppress false positives

```toml
[detection_whitelist]
suppressed_process_names = [
    "cargo", "node", "python3", "brew",
    # add your own trusted tools here
]

suppressed_path_prefixes = [
    "/Users/you/Projects/",
    "/opt/homebrew/",
]
```

The response whitelist (`[whitelist]`) is separate — it means "detect but don't kill/quarantine." The detection whitelist means "don't even generate an alert."

---

## Architecture

```
Sensor Layer        File | Process | Network | Persistence monitors
      ↓
Detection Engine    45 functions, ~95% MITRE ATT&CK user-space coverage
      ↓
Correlation Engine  Attack chain scoring, incident grouping, MITRE tagging
      ↓
Response Engine     Guardrails → Whitelist → Kill / Quarantine / Simulate
      ↓
         ┌──────────────────────┬──────────────────────┐
      AI Layer              UI Layer (Tauri + React)
   StoryLine                Inbox model, history,
   (deterministic           health dashboard,
   + optional Claude)       settings
```

### Detection coverage

| Tactic | Key techniques |
|---|---|
| Execution | Downloaded file execution, interpreter abuse, curl-pipe-bash, LOLBin execution |
| Persistence | LaunchAgent/Daemon modification, crontab, login hooks |
| Privilege Escalation | sudo abuse, setuid/setgid operations |
| Defense Evasion | File type mismatch, indicator removal, security tool tampering |
| Credential Access | Keychain access, browser credential theft, SSH key access |
| Discovery | System/network/filesystem recon chains |
| Lateral Movement | SSH lateral movement |
| Collection | Data staging, screen capture, suspicious archive creation |
| C2 | Beaconing pattern detection (suppresses Apple/Google IPs) |
| Exfiltration | Upload command detection |
| Impact | Ransomware behavior (extension wave, ransom note, backup tampering) |

### Agent self-protection

- **Watchdog** — separate binary that respawns the agent if it dies
- **Config integrity** — SHA256 check on `agent-config.toml` every 60s, reverts tampering
- **Log integrity** — tamper-evident line count + last-line hash
- **Directory permissions** — enforces 0o700 on runtime dirs

---

## Repository structure

```
hound/
├── agents/core-agent/          # Rust EDR engine
│   ├── src/
│   │   ├── main.rs             # Entry point, main loop
│   │   ├── detections.rs       # 45 detection functions, 165 tests
│   │   ├── incidents.rs        # Incident correlation engine
│   │   ├── response.rs         # Response engine with guardrails
│   │   ├── processes.rs        # Process monitoring
│   │   ├── files.rs            # File monitoring
│   │   ├── network.rs          # Network telemetry (lsof polling)
│   │   ├── persistence_monitor.rs
│   │   ├── config.rs           # Hot-reload config + whitelists
│   │   ├── perf.rs             # Per-subsystem performance instrumentation
│   │   └── bin/watchdog.rs     # Watchdog binary
│   └── Cargo.toml
├── apps/desktop/               # Tauri + React desktop UI
│   ├── src/
│   │   ├── App.tsx             # Main app, event subscription, state
│   │   └── components/
│   │       ├── Onboarding.tsx  # 5-screen first-run flow
│   │       ├── AuthScreen.tsx  # Sign-up / sign-in / skip
│   │       ├── IncidentFeed.tsx
│   │       ├── StoryLine.tsx   # Plain-English incident narrative
│   │       ├── HistoryView.tsx
│   │       ├── HealthDashboard.tsx
│   │       └── SettingsView.tsx
│   └── src-tauri/src/lib.rs   # All Tauri commands
├── apps/landing/               # Static marketing pages
├── apps/operator-dashboard/    # Single-file fleet monitoring dashboard
├── runtime/                    # Runtime data (gitignored)
│   ├── agent-config.toml       # Live configuration
│   └── logs/                   # JSONL telemetry
├── scripts/
│   ├── build-installer.sh      # Builds dist/Hound-0.1.0.dmg
│   ├── platform_test.sh        # 8-test pre-beta validation suite
│   └── red_team_test.sh        # 10 attack chain tests (safe, self-cleaning)
└── CLAUDE.md                   # AI assistant context for this codebase
```

---

## CLI flags

```bash
# Run the agent
cargo run --bin core-agent

# Print performance summary and exit (run after 24h for real numbers)
cargo run --bin core-agent -- --perf-report

# Print current whitelist and exit
cargo run --bin core-agent -- --list-whitelist

# Clear the behavioral baseline database
cargo run --bin core-agent -- --clear-baseline

# Run the watchdog
cargo run --bin watchdog
```

---

## Testing

### Unit tests (165 tests, all passing)

```bash
cd agents/core-agent
cargo test
```

### Platform test suite (8 integration tests)

Requires the agent to be running. Tests: incident storm regression, persistence across restart, quarantine, whitelist validation, false positive baseline, baseline consistency, log rotation, watchdog restart.

```bash
./scripts/platform_test.sh          # Run all 8
./scripts/platform_test.sh --test 5 # Run a single test
```

### Red team tests (10 attack chains, safe and self-cleaning)

```bash
./scripts/red_team_test.sh          # Interactive
./scripts/red_team_test.sh --quick  # Auto, 10s gaps between tests
./scripts/red_team_test.sh --test 1 # Single test
```

Tests cover: classic dropper, curl-pipe-bash, persistence, credential access, system recon, data staging + exfil, ransomware, masquerading, indicator removal, privilege escalation.

---

## Building the installer

Produces a signed `.dmg` with drag-to-Applications, LaunchAgent autostart, and a clean uninstaller.

```bash
./scripts/build-installer.sh
# Output: dist/Hound-0.1.0.dmg
```

Open the DMG, drag Hound to `/Applications`, then run `Install Hound.command` to set up LaunchAgents so the agent starts automatically at login.

---

## Desktop UI setup

### Supabase (optional — for auth and fleet telemetry)

The UI supports optional Supabase auth and heartbeat reporting. Without it, everything works — auth is skippable and heartbeats are no-ops.

To enable: copy `.env.example` to `.env` in `apps/desktop/` and fill in your Supabase project URL and anon key.

```bash
cp apps/desktop/.env.example apps/desktop/.env
# edit .env with your values
```

### AI-enhanced StoryLines (optional)

Every incident gets a deterministic plain-English narrative without any API key. To enable Claude Haiku enhancement: open the desktop app → Settings → add your Anthropic API key. It's stored in macOS Keychain, never on disk.

---

## Permissions

Hound needs **Full Disk Access** to monitor all relevant paths. Without it, detection coverage is partial. Grant it in System Settings → Privacy & Security → Full Disk Access.

**Accessibility** is optional — it improves detection of remote-control attacks.

The onboarding flow guides you through both.

---

## Development notes

- The agent defaults to `simulation_mode = true` on any config read error. This is intentional and load-bearing — never change this default.
- The `[detection_whitelist]` and `[whitelist]` sections serve different purposes: detection whitelist = no alert generated; response whitelist = alert generated but no automated action.
- Performance budget: 50ms per subsystem tick. Check `runtime/logs/perf-stats.jsonl` after significant changes. Run with `--perf-report` after 24h of normal use.
- All new detection functions need unit tests: one positive case (detects attack) and one negative case (does not false-positive on normal behavior).

---

## Known limitations

These require Apple's Endpoint Security Framework (kernel extension) and are post-beta:

- **T1055** — Process injection (memory/dylib injection)
- **T1014** — Rootkits
- **T1205** — Traffic signaling (deep packet inspection)
- **T1006** — Direct volume access

User-space ceiling is ~95% meaningful MITRE coverage.

---

## Roadmap

- [ ] 24-hour performance test and false positive audit on real machines
- [ ] End-to-end fresh state test
- [ ] Beta with 10–20 real users
- [ ] Apple notarization
- [ ] Auto-update (Tauri updater)
- [ ] Apple Endpoint Security Framework integration (kernel-level visibility)
