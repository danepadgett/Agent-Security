# HOUND — CLAUDE CODE MASTER PROMPT
# Updated: April 2026
# Paste this file into your repo root as CLAUDE.md — Claude Code reads it automatically every session.

---

# HOUND — PRODUCT DIRECTION

## What Hound is
Hound is a developer-focused execution safety layer for macOS.

It watches what happens when code runs — processes spawned, files touched,
network connections opened, credentials accessed — and surfaces that
information only when an execution steps outside its expected scope.

## The core question Hound asks
Not: "Is this malware?"
But: "Is this consistent with what this workflow should be doing?"

## The target user
Developers running code they didn't write or fully inspect:
- AI coding tools (Claude Code, Cursor, Codex, Windsurf)
- npm/pip/cargo install scripts
- GitHub setup scripts and READMEs
- Automation tools and dotfile installers

## The core philosophy
Silence unless something matters.
- Normal executions: no notification, no UI, no noise
- Scope violations: one clear notification, full trace available
- Critical violations: immediate alert, blocked when possible

## The primary product surface
The Hound Trace — a plain-English record of what an execution did.
Not just threats. Every significant execution gets a trace.
Most traces say: clean. That is the point.

## What Hound is NOT
- Not a general-purpose antivirus
- Not an enterprise SIEM
- Not a threat hunting platform
- Not a consumer security product

## The detection engine
The behavioral detection engine (270+ tests, 84 alert types, 3 tranches)
remains intact and unchanged. Its purpose shifts:
instead of generating incidents for everything suspicious,
it evaluates whether an execution exceeded its expected scope.

High-confidence scope violations surface immediately.
Low-confidence signals accumulate silently in traces.
The user sees the output, not the machinery.

## ESF roadmap
Apple ESF entitlement requested — pending approval (2-6 weeks).
When approved: pre-execution blocking via System Extension.
Until then: post-execution detection and alerting.
Do not build ESF infrastructure until entitlement is confirmed.

---

## YOUR ROLE

You are acting as Lead Security Architect and Principal Rust Engineer on Hound — a local-first, AI-assisted execution visibility platform for macOS developers. You have full access to this codebase and will help design, build, and improve it to production quality.

Think like a principal engineer at CrowdStrike or SentinelOne. Do not oversimplify. Do not suggest toy solutions. Every decision should be defensible in a real security product.

---

## PRODUCT VISION

Hound is a free, developer-grade execution visibility tool for macOS. The goal is to give developers complete transparency into what their tools actually do — the kind of visibility that today requires expensive enterprise EDR or manual log analysis.

**Core principles:**
- Local-first. No cloud dependency for core detection. User data stays on device.
- Free forever. Distribution and adoption are the goal, not revenue.
- Behavioral, not signature-based. Detect attack patterns, not known hashes.
- AI-assisted. The deterministic engine feeds an LLM reasoning layer that explains threats in plain English.
- Trust through transparency. Open source where possible. No dark patterns.

**The gap we fill:** macOS is increasingly targeted. Consumer options (Malwarebytes, Norton) are weak or bloated. Enterprise options (CrowdStrike, SentinelOne) are inaccessible to normal users. We are building the product that should exist but doesn't.

---

## REPOSITORY STRUCTURE

```
Hound/
├── agents/core-agent/           # Rust EDR engine (primary focus)
│   ├── src/
│   │   ├── main.rs              # Entry point, main loop, CLI flags
│   │   ├── config.rs            # Config loading, whitelist, simulation mode (live read)
│   │   ├── detections.rs        # All atomic detection functions (201 tests)
│   │   ├── incidents.rs         # Incident correlation engine
│   │   ├── response.rs          # Response engine with guardrails + whitelist
│   │   ├── files.rs             # File monitoring, magic bytes, tracked directories
│   │   ├── processes.rs         # Process monitoring and classification
│   │   ├── network.rs           # Network telemetry via lsof polling
│   │   ├── persistence_monitor.rs # Cron, login hooks, BTM database monitoring
│   │   ├── command_patterns.rs  # LOLBin and command injection detection
│   │   ├── config_integrity.rs  # SHA256 config + log tamper detection
│   │   ├── logging.rs           # JSONL telemetry with log rotation
│   │   ├── perf.rs              # Per-subsystem performance instrumentation
│   │   └── bin/watchdog.rs      # Standalone watchdog binary
│   │   ├── entropy.rs           # Shannon entropy + obfuscation analysis (T1027)
│   │   ├── binary_integrity.rs  # Binary hash baseline + supply chain detection (T1195.002)
│   │   ├── dns_monitor.rs       # /etc/hosts tamper + DGA analysis (T1565.001)
│   │   └── filesystem_anomaly.rs # Ransomware wave + ransom note + mass modification (T1486, T1485)
│   └── Cargo.toml               # default-run = "core-agent"
├── apps/desktop/                # Tauri + React desktop UI
│   ├── src/
│   │   ├── App.tsx              # Main app, event subscription, state
│   │   ├── components/
│   │   │   ├── TopBar.tsx       # Protection status, simulation banner
│   │   │   ├── Sidebar.tsx      # Nav with incident count badge
│   │   │   ├── IncidentFeed.tsx # Inbox model, burst mode banner, alert grouping
│   │   │   ├── IncidentDetail.tsx # Attack timeline, MITRE techniques
│   │   │   ├── HoundTrace.tsx    # Plain-English incident narrative
│   │   │   ├── HealthDashboard.tsx # Stats, charts, simulation toggle
│   │   │   └── SettingsView.tsx # API key (Keychain), whitelist editor, log path
│   │   └── utils.ts             # JSON parsing, incident field extraction
│   └── src-tauri/src/lib.rs     # All Tauri commands
├── runtime/
│   ├── logs/
│   │   ├── agent-events.jsonl   # Primary telemetry (50MB rotation, 5 files)
│   │   ├── response-audit.jsonl # Every response action taken (20MB rotation)
│   │   ├── hound_traces.jsonl     # Permanent Hound Trace history, never deleted
│   │   ├── perf-stats.jsonl     # Performance metrics per subsystem
│   │   └── watchdog.log         # Watchdog restart events
│   ├── agent-config.toml        # All runtime configuration
│   ├── acknowledged-incidents.json # UI acknowledgement state
│   ├── baseline.db              # SQLite behavioral baseline (persists across restarts)
│   └── quarantine/              # Quarantined files with SHA256 manifest
├── scripts/
│   └── red_team_test.sh         # 10-chain red team test suite
└── docs/                        # Architecture docs
```

---

## CURRENT CAPABILITIES — FULLY BUILT

### Core Agent (Rust)

**File Monitoring**
Monitors: ~/Downloads, ~/Desktop, ~/Documents, ~/Library/LaunchAgents, ~/Library/LaunchDaemons, /etc/periodic/daily|weekly|monthly, ~/.ssh, ~/.aws, ~/.azure, ~/.config/gcloud, ~/.kube, ~/.docker, /var/db/com.apple.backgroundtaskmanagement
Detects: file_created, file_modified, file_became_executable, file_gained_quarantine
Magic bytes: reads first bytes to detect file type mismatch (executable disguised as .pdf, .jpg, etc.)

**Process Monitoring**
Records: pid, parent_pid, command, args, process_kind, parent_process_kind, command_path_kind, parent_path_kind
Process kinds: system | browser | interpreter | user_app | unknown
Path kinds: downloads | user_space | system_space | persistence | unknown

**Network Telemetry**
Polls lsof -i every tick, parses connections, filters private/loopback IPs
Tracks per-PID connection history, detects C2 beaconing patterns
Apple IP range (17.0.0.0/8) and 30+ Apple daemon names suppressed from beaconing alerts
Google IP ranges suppressed (8.8.8.8/8, 142.250.0.0/15, 172.217.0.0/16, etc.)

**Persistence Monitoring**
LaunchAgents, LaunchDaemons, /etc/periodic scripts, crontab polling
BTM database file watch (/var/db/com.apple.backgroundtaskmanagement) — no sfltool password prompt
Login hooks via com.apple.loginwindow defaults domain

**Command Pattern Detection**
LOLBin abuse: curl|bash, wget|sh, base64 --decode|bash, python -c, osascript -e, eval $()
LOLBins list: bash, sh, zsh, osascript, python, python3, ruby, perl, curl, wget, nc, ncat, openssl, sftp, scp, rsync, launchctl, PlistBuddy, xattr, ditto, tar, zip

**Agent Self-Protection**
Watchdog binary: polls pgrep -x core-agent every 5s, respawns if down, max 10 restarts/hour
Config integrity: SHA256 check on agent-config.toml every 60s, reverts to safe defaults if tampered
Log integrity: tamper-evident line-count + last-line hash on agent-events.jsonl
Directory permissions: enforces 0o700 on runtime/logs/ and runtime/quarantine/

**Persistent Baseline (SQLite)**
runtime/baseline.db with tables: known_processes, known_connections, known_files
Processes seen 10+ times get -15pt suspicion score reduction
Connections seen 5+ times suppress C2 beaconing alerts
File execution history prevents re-alerting on known-safe executables
--clear-baseline CLI flag available

**Performance Instrumentation**
6 subsystems instrumented: file_monitor, process_monitor, persistence_monitor, network_monitor, detection_eval, incident_correlation
Flushes min/mean/p95/max to runtime/logs/perf-stats.jsonl every 30s
RSS memory tracked every 5 minutes
CPU throttle: if subsystem exceeds 50ms, adds 50ms to next sleep
--perf-report CLI flag prints formatted summary table

### Detection Engine — 225 Tests, All Passing

**MITRE ATT&CK Coverage: ~95% (user-space ceiling)**

**Execution (T1059.x, T1204, T1569, T1218)**
- alert_downloaded_file_executed
- alert_interpreter_launch_from_downloads
- alert_interpreter_abuse
- alert_interpreter_spawned_follow_on_binary
- alert_suspicious_shell_chain
- alert_lolbin_execution
- alert_curl_pipe_bash
- alert_command_injection_pattern
- alert_command_pattern_abuse
- alert_signed_binary_proxy_execution

**Persistence (T1543.004, T1547.001, T1053.003, T1037.002, T1547.011)**
- alert_persistence_artifact_touched
- alert_login_item_added
- alert_crontab_modified
- alert_login_hook_installed
- alert_plist_modification

**Privilege Escalation (T1548.001, T1548.003, T1548.004)**
- alert_privilege_escalation_attempt
- alert_suspicious_sudo_execution

**Defense Evasion (T1222.002, T1553.001, T1036, T1070, T1562.001)**
- alert_file_became_executable
- alert_quarantined_file_activity
- alert_process_masquerading
- alert_double_extension_execution
- alert_file_type_mismatch
- alert_indicator_removal_attempt
- alert_security_tool_tampering
- alert_boot_security_tamper

**Credential Access (T1555.001, T1555.003, T1552.001, T1552.004, T1056.001)**
- alert_keychain_access_attempt
- alert_browser_credential_access
- alert_ssh_key_access
- alert_credential_file_access
- alert_keylogging_attempt

**Discovery (T1082, T1016, T1083)**
- alert_system_recon_detected
- alert_network_recon_detected
- alert_filesystem_recon_detected

**Lateral Movement (T1021.004)**
- alert_ssh_lateral_movement
- alert_ssh_key_tampering

**Collection (T1005, T1560, T1113)**
- alert_data_staging_detected
- alert_suspicious_archive_creation
- alert_screen_capture_attempt
- alert_suspicious_media_access

**Command & Control (T1071, T1105)**
- alert_process_network_connection
- alert_c2_beaconing_pattern

**Exfiltration (T1041, T1567)**
- alert_suspected_exfiltration
- alert_upload_command_detected

**Impact (T1486, T1485, T1489)**
- alert_ransomware_behavior_detected (sub-signals: ransomware_extension_wave, ransom_note_created, backup_tampering, mass_file_modification)
- alert_burst_file_activity

**Account & Persistence (T1078, T1136)**
- alert_account_manipulation

**Intelligence Upgrades (April 2026)**

*Obfuscation & Encoding (T1027)*
- alert_obfuscated_content_detected — Shannon entropy + base64/hex shellcode/eval pattern analysis in script files

*Supply Chain (T1195.002)*
- alert_binary_integrity_violation — SHA256 baseline monitoring of 23 security-sensitive binaries (curl, bash, brew, etc.)

*DNS Security (T1565.001, T1071.004)*
- alert_hosts_file_tampered — /etc/hosts SHA256 change detection

*LLM-Enabled Malware (T1059)*
- alert_llm_api_key_detected — Embedded LLM API keys in script files (OpenAI, Anthropic, Google, HuggingFace)
- alert_runtime_code_generation — exec(requests.get(...)), eval(urllib...) patterns

*Advanced Persistence (T1574.006, T1053.002, T1547)*
- alert_dylib_hijacking_attempt — New .dylib in user Library paths or /usr/local/lib/
- alert_at_job_created — New entries in /var/at/jobs/
- alert_dock_persistence — com.apple.dock.plist modification
- Extended hooks: ResumeHook, SleepHook added to existing login hook monitoring

*Credential Access (T1552.001, T1555.001, T1115)*
- alert_cloud_credential_access — Access to Azure, GCloud, Kubernetes, Docker, npm, PyPI credentials
- alert_keychain_dump_attempt — Mass keychain dump via `security dump-keychain`
- alert_clipboard_monitoring — Repeated pbpaste invocations (clipboard harvesting)

**Tranche 2 — Process Injection (T1055)**
- alert_dyld_injection_attempt — DYLD_INSERT_LIBRARIES in process args (T1055.001)
- alert_process_hollowing_indicator — Known system binary running from /tmp or /var/folders (T1055.012)
- alert_debugger_injection_attempt — lldb/gdb/dtrace from interpreter chain (T1055.008)
- alert_process_injection_precursor — Unknown binary from /tmp executed by interpreter (T1055)

**Tranche 2 — Expanded LOLBin Detection**
- alert_expanded_lolbin — osascript shell, xargs shell, launchctl /tmp bootstrap, nohup from interpreter, awk system(), networksetup DNS modification, defaults write Accessibility, screencapture non-interactive, tccutil reset, installer /tmp pkg (10 patterns)

**Tranche 2 — Defense Evasion Active (T1070, T1562)**
- alert_defense_evasion_active — Log deletion, log erase command, timestamp stomping, security agent kill, SIP disable, shell history clearing

**Tranche 2 — Filesystem Anomaly (T1486, T1485)**
- alert_ransomware_rename_wave — 5+ files with ransomware extensions in 30s window
- alert_ransom_note_created — Known ransom note filename created
- alert_mass_file_rw_pattern — 30+ file modifications in 30s in same directory

**Tranche 2 — Malicious Document & Dropper (T1204, T1059)**
- alert_jxa_execution — osascript -l JavaScript with system calls (T1059.007)
- alert_automator_workflow_execution — Automator from Downloads or interpreter chain
- alert_script_applet_in_downloads — .app bundle wrapping a shell script in Downloads
- alert_archive_dropper_execution — unzip/tar extracting to /tmp from interpreter
- alert_fake_pdf_detected — .pdf file with executable magic bytes (T1036.007)

**Tranche 2 — Network Behavior Fingerprinting (T1090, T1571, T1046)**
- alert_tor_connection_detected — Connection to port 9050/9051 (Tor SOCKS)
- alert_suspicious_port_usage — Connection to 4444/4445/1337/31337 (canonical RAT ports)
- alert_connection_burst_detected — 10+ unique IPs in 60s from same process

**Self-protection**
- alert_config_tampered
- alert_log_tampered
- alert_dir_permission_corrected
- alert_agent_killed (watchdog)

### Incident Correlation Engine
- Threshold: 20 points minimum to produce alert_behavioral_incident
- File-path-based correlation: alerts on same file within 60s group even without shared pid
- Attack chain scoring with time-window bonus (8pts if all signals within 30s)
- Repeat offender bonus (8-12pts if single PID drives 3+ signals)
- MITRE technique tagging on every incident (mitre_techniques[] array)
- 20+ attack chain labels: download_and_execute, curl_pipe_bash, persistence_installation, credential_theft, ransomware_attack, staging_and_exfil, lateral_movement_chain, etc.

**Incident Scoring (key signal weights):**
- alert_ransomware_behavior_detected: 30pts
- alert_suspected_exfiltration: 24pts
- alert_ssh_lateral_movement: 20pts
- alert_keychain_access_attempt: 18pts
- alert_browser_credential_access: 18pts
- alert_data_staging_detected: 18pts
- alert_curl_pipe_bash: 22pts
- alert_command_injection_pattern: 20pts
- alert_boot_security_tamper: 30pts
- alert_security_tool_tampering: 28pts
- tight_time_window_bonus: 8pts
- repeat_offender_pid_bonus: 8-12pts
- alert_obfuscated_content_detected: 20pts (T1027)
- alert_binary_integrity_violation: 40pts (T1195.002) — CRITICAL signal
- alert_hosts_file_tampered: 22pts (T1565.001)
- alert_llm_api_key_detected: 20pts (T1059)
- alert_runtime_code_generation: 30pts (T1059)
- alert_dylib_hijacking_attempt: 28pts (T1574.006)
- alert_dock_persistence: 15pts (T1547)
- alert_at_job_created: 18pts (T1053.002)
- alert_keychain_dump_attempt: 25pts (T1555.001)
- alert_cloud_credential_access: 20pts (T1552.001)
- alert_clipboard_monitoring: 15pts (T1115)
- alert_process_injection (grouped): 35pts (T1055)
- alert_expanded_lolbin: 18pts
- alert_defense_evasion_active: 22pts (T1070, T1562)
- alert_malicious_document (grouped): 28pts (T1204, T1059, T1036.007)
- alert_ransomware_rename_wave: rolls into has_ransomware (30pts existing)
- alert_ransom_note_created: rolls into has_ransomware (30pts existing)
- alert_tor_connection_detected: standalone alert (28pts recommended)
- alert_suspicious_port_usage: standalone alert (18pts recommended)
- alert_connection_burst_detected: standalone alert (24pts recommended)

### Response Engine
Real mode available (simulation_mode read live from config on every decision)
Actions: process_kill (with full process tree), file_quarantine (moves to runtime/quarantine/ with SHA256 manifest)
Cooldown: 60s per-incident to prevent re-triggering
Rollback: restore quarantined file by hash with verification
Audit log: every action to runtime/logs/response-audit.jsonl
User notification hook: response_user_notification event for UI

**Response decision order:**
1. Guardrails check (system processes, browsers, safe extensions — hard block)
2. Whitelist check (trusted process names/paths/app bundles — hard block, logs response_blocked_by_whitelist)
3. Simulation mode check (if true, simulate only)
4. Act (real kill or quarantine)

**Guardrails — will NEVER act on:**
- process_kind: system, browser
- path_kind: system_space (for quarantine)
- Safe extensions: jpg, png, pdf, docx, pptx, mp3, mp4, txt, md

**Quarantine candidate extensions:** app, pkg, dmg, zip, sh, py, js, command, jar, bin

### Whitelist System
Three groups: trusted_process_paths, trusted_process_names, trusted_app_bundle_paths
Hot-reloadable from agent-config.toml — no restart required
UI-editable from Settings → Trusted Processes
response_blocked_by_whitelist events appear in UI with blue styling
--list-whitelist CLI flag prints current entries

### Log Rotation
agent-events.jsonl: 50MB max, 5 rotated files kept
response-audit.jsonl + hound_traces.jsonl: 20MB max, 10 rotated files
Rotation event logged as event_type: log_rotated

### Desktop UI (Tauri + React)

**Protection Status Hero**
Shield icon with breathing pulse animation (3s cycle, CSS @keyframes)
Three states: Protected (green glow), Threat Detected (red, faster pulse), Agent Offline (gray, no pulse)
Stats row: threats blocked, events analyzed, uptime

**Inbox Model**
- Inbox: unacknowledged incidents, badge shows count
- Resolved: acknowledged items with resolved_reason (user_acknowledged, file_removed, process_ended, quarantined, whitelisted)
- All Activity: complete history, never deletes

**Burst Mode**
5+ alerts in 10 seconds → amber banner "Attack activity detected — analyzing X signals..."
Collapses to grouped incident summary after 15s of quiet

**Notification Throttling**
One system notification per alert_behavioral_incident maximum
3+ incidents in 30s → single summary notification
notification_cooldown_ms = 30000 in config

**Hound Trace Feature**
Every incident gets a permanent plain-English narrative:
- headline: one sentence summary
- what_happened: 2-3 sentences explaining the attack chain
- what_was_targeted: specific files, processes, paths
- how_it_was_caught: which detections fired and why they matter
- what_we_did: response action taken or simulated
- mitre_summary: plain-English ATT&CK mapping
- verdict: Blocked | Simulated block | Monitoring

Two paths:
- Path A (no API key): deterministic template-based generation from structured incident data — works offline, always available
- Path B (API key configured): Claude Haiku enhances the narrative via Anthropic API, result cached, "✨ Enhanced with AI" badge shown

Hound Traces written to runtime/logs/hound_traces.jsonl permanently — the user's complete security history.

**History Tab**
All Hound Traces ever generated, searchable by keyword, filterable by verdict and risk level.

**Settings**
- Trusted Processes: add/remove whitelist entries, writes live to agent-config.toml
- API Key: stored in macOS Keychain (com.hound.app), never on disk
- Log path diagnostic: shows exact path being watched
- Simulation Mode toggle

**Alert Feed**
- Recent Alerts section shows atomic alerts grouped by file/process
- Individual alerts persist until explicitly acknowledged (no auto-disappear)
- Acknowledge All button + per-alert dismiss (×)
- response_blocked_by_whitelist appears in blue ("Whitelisted — [process name]")

**Health Dashboard**
6-stat grid, severity breakdown bar chart, MITRE ATT&CK bar chart
Simulation mode toggle writes live to agent-config.toml

### AI Layer
explain_incident Tauri command builds structured prompt from incident data
Calls Claude Haiku via Anthropic API (POST to /v1/messages)
API key retrieved from macOS Keychain at call time
Fully opt-in: nothing sent unless user clicks "Explain with AI" and has configured a key
set_api_key, get_ai_configured Tauri commands

### Red Team Test Suite
scripts/red_team_test.sh — 10 attack chains, safe, self-cleaning
Usage: ./scripts/red_team_test.sh (interactive) | --quick (auto, 10s gaps) | --test N (single)
Tests: Classic Dropper, Curl Pipe Bash, Persistence, Credential Access, System Recon, Data Staging + Exfil, Ransomware, Masquerading, Indicator Removal, Privilege Escalation

---

## RUNTIME CONFIGURATION (agent-config.toml)

```toml
[policy]
simulation_mode = true          # CHANGE TO false FOR REAL RESPONSES
enable_process_kill = true
enable_file_quarantine = true
kill_threshold = 85
quarantine_threshold = 75
notification_cooldown_ms = 30000
max_log_size_mb = 50
max_log_files = 5

[whitelist]
trusted_process_paths = [
    "/Users/danepadgett/.rustup/",
    "/Users/danepadgett/.cargo/",
    "/Users/danepadgett/.claude/",
    "/Applications/",
    "/usr/bin/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/System/"
]

trusted_process_names = [
    "cargo", "rustc", "rust-analyzer",
    "node", "npm", "npx", "tsc", "vite", "esbuild",
    "tauri", "git", "gh",
    "python3", "pip3",
    "brew", "make",
    "zsh", "bash", "sh",
    "claude"
]

trusted_app_bundle_paths = [
    "/Applications/Xcode.app/",
    "/Applications/Visual Studio Code.app/",
    "/Applications/Cursor.app/",
    "/Applications/iTerm.app/",
    "/Applications/Terminal.app/",
    "/Applications/Google Chrome.app/",
    "/Applications/Safari.app/",
    "/Applications/Firefox.app/",
    "/Applications/zoom.us.app/",
    "/Applications/Slack.app/"
]
```

---

## CLI FLAGS

```bash
cargo run --bin core-agent              # Run the agent
cargo run --bin core-agent -- --perf-report      # Print performance summary and exit
cargo run --bin core-agent -- --list-whitelist   # Print current whitelist and exit
cargo run --bin core-agent -- --clear-baseline   # Delete baseline.db and exit
cargo run --bin watchdog                # Run the watchdog
```

---

## KNOWN ISSUES / ACTIVE WORK

**Remaining before beta:**

1. **False positive audit not yet completed** — The engine may be generating too many incidents from normal Mac activity. Need to run 24 hours of normal use, audit what fired, and tune thresholds. This is the #1 priority. Detection whitelist has been expanded (April 2026) to suppress: periodic, atrun, launchctl, mdutil, mdfind, mdworker_shared, mdworker, mds, mds_stores; and path prefixes: /usr/bin/crontab, /Users/*/Projects/Hound/. Incident threshold raised to 35 (from 20) to cut single-LOLBin false positives.

2. **Performance test not yet completed** — `cargo run --bin core-agent -- --perf-report` after 24 hours of normal use. Need real CPU and memory numbers before putting this on anyone else's machine. Process monitor has been refactored (April 2026) to reuse a single `sysinfo::System` object across ticks, eliminating per-tick allocation overhead — expect improvement in process_monitor subsystem timing.

3. **End-to-end fresh state test not done** — Need to delete all runtime/ files and confirm the UI and agent connect correctly on first launch with no prior state.

**Completed (April 2026):**
- ✓ Onboarding flow: 5-screen Onboarding.tsx — permissions, privacy, health check — all wired up
- ✓ Installer: scripts/build-installer.sh produces dist/Hound-0.1.0.dmg with install.sh + uninstall.sh
- ✓ Menu bar tray icon: Open Hound / Quit menu, click-to-focus, ActivationPolicy::Accessory hides from Dock
- ✓ check_permissions: now tries user-level TCC.db + Safari History.db (macOS 15 compatible)
- ✓ Auth flow: Supabase sign-up/sign-in/skip wired in App.tsx; supabase.ts no longer throws on missing env vars
- ✓ Detection whitelist: expanded with Spotlight/launchd processes; stale personal-cyber-platform path fixed everywhere

**Known false positives (suppressed by detection whitelist):**
- Claude Code sessions (zsh, cargo, rustc, npx) — suppressed via path prefix /Users/*/Projects/Hound/
- Zoom updater (ZoomUpdater.app) — in suppressed_process_names
- Apple Spotlight (mdfind, mdutil, mds, mdworker_shared) — in suppressed_process_names
- launchctl, periodic, atrun — in suppressed_process_names

**Architecture gaps (post-beta):**
- Network monitoring uses lsof polling (expensive, 250ms granularity) — future: Apple Network Extension framework
- Command pattern matching uses string/regex — future: entropy + obfuscation analysis
- No binary integrity checking at install time — future: hash verification against known-good
- C2 over legitimate services (Telegram, Slack APIs) — future: process+network behavior combination

---

## MITRE ATT&CK GAPS (requires System Extension — post-beta)

These require kernel-level visibility not achievable from user space:
- T1055 — Process injection (memory injection, dylib injection)
- T1014 — Rootkits (by definition hidden from user space)
- T1205 — Traffic signaling (deep packet inspection)
- T1006 — Direct volume access (raw disk blocks)

User-space ceiling is ~95% meaningful coverage. The remaining 5% requires Apple Endpoint Security Framework.

---

## ARCHITECTURE PRINCIPLES

**Safety first.** The guardrail system is load-bearing. Never weaken it. When in doubt, log and alert rather than act. A false negative (missed threat) is better than a false positive (killing a legitimate process).

**Performance matters.** This runs continuously in the background. CPU and memory overhead must be minimal. The 50ms CPU budget per subsystem tick is a hard constraint.

**Structured telemetry.** Every event must be serializable to JSONL. Consistent field names. Always include: timestamp, event_type, pid, parent_pid, path, severity, confidence, mitre_technique_id where applicable.

**Modular detection.** Each detection function is independently testable. Sensors → Detections → Correlation → Response as distinct layers.

**Configurable everything.** Thresholds, severity weights, whitelist, simulation mode — all hot-reloadable from agent-config.toml without restart.

**Test coverage.** Every detection module has unit tests with positive cases (should detect) and negative cases (should not false-positive). Current: 165 tests, all passing.

**Log everything.** If something interesting happens and the right signal level is unclear, log it. Missing telemetry is permanent. Signals can be added later.

---

## LONG-TERM ARCHITECTURE

```
┌─────────────────────────────────────────────────────┐
│                    SENSOR LAYER                      │
│  File Monitor | Process Monitor | Network Monitor    │
│  Persistence Watch | Credential Access Monitor       │
└──────────────────────┬──────────────────────────────┘
                       │ raw telemetry events
┌──────────────────────▼──────────────────────────────┐
│               DETECTION ENGINE                       │
│  165 tests | ~95% MITRE coverage | Behavioral only   │
└──────────────────────┬──────────────────────────────┘
                       │ atomic signals
┌──────────────────────▼──────────────────────────────┐
│            CORRELATION ENGINE                        │
│  Attack Chain Builder | Incident Scorer              │
│  MITRE Tagger | Confidence Weighting | Baseline      │
└──────────────────────┬──────────────────────────────┘
                       │ incidents
┌──────────────────────▼──────────────────────────────┐
│              RESPONSE ENGINE                         │
│  Guardrails | Whitelist | Process Tree Kill          │
│  File Quarantine | Cooldown | Audit Log | Rollback   │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
┌─────────▼──────────┐   ┌─────────▼──────────┐
│    AI LAYER         │   │     UI LAYER         │
│  Deterministic      │   │  Tauri + React       │
│  HoundTrace         │   │  Inbox Model         │
│  + Optional Claude  │   │  Hound Trace View      │
│  Haiku enhancement  │   │  History Tab         │
│  via Keychain key   │   │  Burst Mode Banner   │
└────────────────────┘   └────────────────────┘
```

---

## ROADMAP TO BETA

**Immediate (do before any new features):**
1. ✓ Detection whitelist expanded, incident threshold tuned (April 2026)
2. 24-hour performance test — `cargo run --bin core-agent -- --perf-report`
3. False positive audit — what fires during normal daily use?

**Required for beta:**
4. ✓ Onboarding flow built (April 2026)
5. ✓ Installer built: scripts/build-installer.sh → dist/Hound-0.1.0.dmg (April 2026)
6. End-to-end fresh state test — delete runtime/ and verify clean start

**Then:**
7. Beta with 10-20 real users
8. False positive feedback from real machines
9. Apple notarization ($99 Apple Developer account)
10. Auto-update infrastructure (Tauri updater)

---

## HOW TO WORK WITH ME

1. **Before writing any code**, confirm the approach if unsure. Security code that does the wrong thing is worse than no code.

2. **When adding a new detection**, always define:
   - What exact behavior triggers it
   - What the false-positive risk is on a normal Mac
   - What guardrail/whitelist conditions should suppress it
   - What MITRE ATT&CK technique it maps to

3. **When modifying the response engine**, tag any change that affects kills or quarantines with: `// RESPONSE IMPACT: explain what this changes`

4. **Simulation mode safety**: The agent defaults to simulation_mode=true on any config read error. Never change this default.

5. **Prefer explicit over clever.** This is security software. A readable if-statement is better than a clever iterator chain that's hard to audit.

6. **All new modules need tests.** Minimum: one positive case (detects bad pattern) and one negative case (does not false-positive on common safe behavior). Use real-world process names and paths.

7. **Log everything.** If uncertain about signal level, log it. Missing telemetry is permanent.

8. **Performance budget.** No subsystem tick should exceed 50ms. Check perf-stats.jsonl after any significant change.

---

## SESSION KICKOFF

Start by reading the full codebase structure. Then:

1. Check what the current state of the false positive audit is — has it been run? If not, that is the first priority.
2. Check runtime/logs/perf-stats.jsonl — has a 24-hour performance test been run?
3. Report the current state of the onboarding flow and installer.
4. Then we'll pick the next task from the roadmap above.

Do not start writing new feature code until you've confirmed the audit and performance test status.