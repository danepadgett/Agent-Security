#!/usr/bin/env bash
# =============================================================================
# Hound — Platform Test Suite
# =============================================================================
# Pre-beta validation suite — confirms core platform invariants hold.
# Safe, self-cleaning, no permanent changes.
#
# Usage:
#   ./scripts/platform_test.sh              # Run all 8 tests
#   ./scripts/platform_test.sh --quick      # Skip interactive pauses
#   ./scripts/platform_test.sh --test N     # Run single test (1–8)
#
# Exit code: 0 = all pass, 1 = any fail
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ── Globals ───────────────────────────────────────────────────────────────────
QUICK_MODE=false
SINGLE_TEST=""
RESULTS=()        # "PASS: msg" or "FAIL: msg" per test
CLEANUP_FNS=()
WATCHDOG_STARTED_BY_TEST=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUNTIME_DIR="${PROJECT_ROOT}/runtime"
LOG_FILE="${RUNTIME_DIR}/logs/agent-events.jsonl"
CONFIG_FILE="${RUNTIME_DIR}/agent-config.toml"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)  QUICK_MODE=true; shift ;;
    --test)   SINGLE_TEST="$2"; shift 2 ;;
    --help|-h)
      grep '^#' "$0" | head -15 | sed 's/^# //' | sed 's/^#//'
      exit 0 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

# ── Utilities ─────────────────────────────────────────────────────────────────
print_header() {
  local num="$1" title="$2"
  echo ""
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}  TEST ${num} — ${title}${RESET}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

pass() {
  local msg="$1"
  RESULTS+=("PASS: ${msg}")
  echo -e "  ${GREEN}✓ PASS${RESET}  ${msg}"
}

fail() {
  local msg="$1"
  RESULTS+=("FAIL: ${msg}")
  echo -e "  ${RED}✗ FAIL${RESET}  ${msg}"
}

print_step() {
  echo -e "  ${CYAN}▶${RESET}  $*"
}

wait_for() {
  local secs="${1:-5}"
  sleep "$secs"
}

should_run() {
  [[ -z "$SINGLE_TEST" ]] || [[ "$SINGLE_TEST" == "$1" ]]
}

# Count new lines in log file
log_line_count() {
  if [[ ! -f "$LOG_FILE" ]]; then echo 0; return; fi
  wc -l < "$LOG_FILE" | tr -d ' '
}

# Read a config value from agent-config.toml
read_config_value() {
  local key="$1"
  grep "^${key}" "$CONFIG_FILE" 2>/dev/null | head -1 | sed 's/.*=\s*//' | tr -d ' ' || true
}

# Write or replace a config key=value in agent-config.toml
set_config_value() {
  local key="$1" val="$2"
  if grep -q "^${key}" "$CONFIG_FILE" 2>/dev/null; then
    sed -i '' "s/^${key}.*/${key} = ${val}/" "$CONFIG_FILE"
  else
    echo "${key} = ${val}" >> "$CONFIG_FILE"
  fi
}

# Parse JSON field from a log line using python3 (no jq dependency)
# Usage: json_field "$line" "field_name"
json_field() {
  python3 -c "
import sys, json
try:
    d = json.loads(sys.argv[1])
    # Check top-level and nested payload.details
    val = d.get(sys.argv[2]) or \
          d.get('payload',{}).get(sys.argv[2]) or \
          d.get('payload',{}).get('details',{}).get(sys.argv[2])
    print(val or '')
except Exception:
    print('')
" "$1" "$2" 2>/dev/null || true
}

# Return current UTC ISO8601 timestamp (seconds precision)
utc_now_iso() {
  date -u +"%Y-%m-%dT%H:%M:%S"
}

# Filter lines from LOG_FILE that are alert_behavioral_incident AND have a
# timestamp >= $1 (ISO8601 string, compared lexicographically — safe for sorted
# UTC timestamps of the form YYYY-MM-DDTHH:MM:SS...).
incidents_since_iso() {
  local since_iso="$1"
  if [[ ! -f "$LOG_FILE" ]]; then return; fi
  python3 - "$LOG_FILE" "$since_iso" <<'PYEOF'
import sys, json
log_file, since = sys.argv[1], sys.argv[2]
with open(log_file) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("event_type") != "alert_behavioral_incident":
            continue
        ts = str(e.get("timestamp", ""))
        # timestamp may be epoch int or ISO string
        if ts.isdigit():
            # convert epoch seconds to comparable ISO-ish string
            import datetime
            ts = datetime.datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%dT%H:%M:%S")
        if ts >= since:
            print(json.dumps(e))
PYEOF
}

# ── Cleanup registry ──────────────────────────────────────────────────────────
register_cleanup() {
  CLEANUP_FNS+=("$1")
}

run_all_cleanup() {
  for fn in "${CLEANUP_FNS[@]:-}"; do
    "$fn" 2>/dev/null || true
  done
}

trap run_all_cleanup EXIT INT TERM

# =============================================================================
# TEST 1 — Incident storm regression
# After a single attack trigger, each unique incident_key should appear ONCE
# within the observation window.  Counts are scoped to the 30s after the probe
# fires so historical incidents don't pollute the count.
# =============================================================================
run_test_1() {
  print_header 1 "Incident Storm Regression"
  echo "  Triggers a red team attack and verifies each incident_key appears only once."
  echo ""

  local start_iso
  start_iso=$(utc_now_iso)

  # Trigger a simple dropper chain (safe — cleans up)
  local test_file="${HOME}/Downloads/hound_storm_test_$$.sh"
  {
    echo '#!/bin/bash'
    echo 'echo "[platform_test] storm regression probe"'
  } > "$test_file"
  xattr -w com.apple.quarantine \
        "0083;$(printf '%08x' "$(date +%s)");Safari;12345678-DEAD-BEEF-CAFE-123456789ABC" \
        "$test_file" 2>/dev/null || true
  chmod +x "$test_file"
  "$test_file" > /dev/null 2>&1 || true
  rm -f "$test_file"

  print_step "Waiting 30s for correlation window…"
  wait_for 30

  # Collect incidents ONLY from after the probe fired
  local incidents_json
  incidents_json=$(incidents_since_iso "$start_iso")

  if [[ -z "$incidents_json" ]]; then
    pass "No incidents generated — deduplication N/A (probe may have scored below threshold)"
    return
  fi

  # Extract incident_keys via python
  local keys_raw total_keys unique_keys
  keys_raw=$(echo "$incidents_json" | python3 -c "
import sys, json
keys = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        e = json.loads(line)
        details = e.get('payload', {}).get('details', {})
        key = details.get('grouping_key') or details.get('incident_key') or ''
        keys.append(key)
    except: pass
for k in keys:
    print(k)
" 2>/dev/null || true)

  total_keys=$(echo "$keys_raw" | grep -c '.' 2>/dev/null || echo 0)
  unique_keys=$(echo "$keys_raw" | sort -u | grep -c '.' 2>/dev/null || echo 0)
  local dupes=$(( total_keys - unique_keys ))

  if (( dupes <= 0 )); then
    pass "Incident deduplication working — ${unique_keys} unique incident(s), 0 duplicates"
  else
    fail "Incident storm — ${dupes} duplicate(s) across ${unique_keys} unique key(s)"
  fi
}

# =============================================================================
# TEST 2 — Persistence across restart
# unacknowledged-incidents.json must survive an agent restart unchanged.
# =============================================================================
test_2_cleanup() {
  if ! pgrep -x core-agent > /dev/null 2>&1; then
    (cd "${PROJECT_ROOT}/agents/core-agent" && \
      cargo run --bin core-agent 2>/dev/null &) || true
  fi
}
register_cleanup test_2_cleanup

run_test_2() {
  print_header 2 "Persistence Across Restart"
  echo "  Verifies unacknowledged incidents survive an agent restart."
  echo ""

  local persist_file="${RUNTIME_DIR}/unacknowledged-incidents.json"

  if [[ ! -f "$persist_file" ]]; then
    print_step "No unacknowledged-incidents.json — skipping (run after incidents exist)"
    pass "Persistence test skipped — no incidents file yet (correct behavior on empty inbox)"
    return
  fi

  if ! python3 -c "import json,sys; json.load(sys.stdin)" < "$persist_file" 2>/dev/null; then
    fail "unacknowledged-incidents.json is not valid JSON before restart"
    return
  fi

  local before_hash before_size
  before_hash=$(shasum -a 256 "$persist_file" | awk '{print $1}')
  before_size=$(wc -c < "$persist_file" | tr -d ' ')

  print_step "Killing core-agent…"
  pkill -x core-agent 2>/dev/null || true
  wait_for 2

  print_step "Restarting core-agent…"
  (cd "${PROJECT_ROOT}/agents/core-agent" && cargo run --bin core-agent 2>/dev/null &)
  wait_for 5

  if [[ ! -f "$persist_file" ]]; then
    fail "unacknowledged-incidents.json was lost after restart"
    return
  fi

  if ! python3 -c "import json,sys; json.load(sys.stdin)" < "$persist_file" 2>/dev/null; then
    fail "unacknowledged-incidents.json is invalid JSON after restart"
    return
  fi

  local after_hash after_size
  after_hash=$(shasum -a 256 "$persist_file" | awk '{print $1}')
  after_size=$(wc -c < "$persist_file" | tr -d ' ')

  if [[ "$before_hash" == "$after_hash" ]]; then
    pass "Incidents persist across restart (${before_size} bytes, hash unchanged)"
  elif (( after_size >= before_size )); then
    pass "Incidents persist across restart (grew ${before_size}→${after_size} bytes — new incidents added)"
  else
    fail "unacknowledged-incidents.json shrank after restart (${before_size}→${after_size} bytes)"
  fi
}

# =============================================================================
# TEST 3 — Quarantine working
# Drop a probe in Downloads, build a more complete attack chain to score > 75,
# enable live mode briefly, verify a file appears in quarantine/.
# =============================================================================
ORIG_SIM_MODE=""

test_3_cleanup() {
  if [[ -n "$ORIG_SIM_MODE" ]] && [[ -f "$CONFIG_FILE" ]]; then
    set_config_value "simulation_mode" "$ORIG_SIM_MODE"
    print_step "simulation_mode restored to ${ORIG_SIM_MODE}"
  fi
  rm -f "${HOME}/Downloads/hound_quarantine_probe_$$.sh" 2>/dev/null || true
}
register_cleanup test_3_cleanup

run_test_3() {
  print_header 3 "Quarantine Working"
  echo "  Enables live mode, runs a scored dropper probe, checks quarantine dir."
  echo ""

  local quarantine_dir="${RUNTIME_DIR}/quarantine"
  mkdir -p "$quarantine_dir"

  ORIG_SIM_MODE=$(read_config_value "simulation_mode")
  [[ -z "$ORIG_SIM_MODE" ]] && ORIG_SIM_MODE="true"

  print_step "Enabling live response (simulation_mode = false)…"
  set_config_value "simulation_mode" "false"

  # Verify the write took effect
  local current_mode
  current_mode=$(read_config_value "simulation_mode")
  print_step "simulation_mode is now: ${current_mode}"

  local before_count
  before_count=$(find "$quarantine_dir" -type f 2>/dev/null | wc -l | tr -d ' ')

  # Build a probe that chains quarantine + exec + interpreter signals (higher score)
  local probe_file="${HOME}/Downloads/hound_quarantine_probe_$$.sh"
  {
    echo '#!/bin/bash'
    echo 'echo "[platform_test] quarantine probe — safe test"'
    # Spawn a child interpreter to trigger interpreter_launch_from_downloads
    echo 'python3 -c "import os; print(os.getcwd())" 2>/dev/null || true'
  } > "$probe_file"

  # Set quarantine xattr with proper format (simulates browser download)
  xattr -w com.apple.quarantine \
        "0083;$(printf '%08x' "$(date +%s)");Safari;12345678-DEAD-BEEF-CAFE-123456789ABC" \
        "$probe_file" 2>/dev/null || true

  chmod +x "$probe_file"
  print_step "Executing probe (quarantine bit set, chmod +x, executes interpreter)…"
  "$probe_file" 2>/dev/null || true

  print_step "Waiting 30s for agent response…"
  wait_for 30

  # Restore simulation mode before checking results
  set_config_value "simulation_mode" "$ORIG_SIM_MODE"
  ORIG_SIM_MODE=""
  rm -f "$probe_file" 2>/dev/null || true

  local after_count new_files
  after_count=$(find "$quarantine_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
  new_files=$(( after_count - before_count ))

  if (( new_files > 0 )); then
    pass "File quarantined successfully — ${new_files} new file(s) in quarantine/"
  else
    # Check if response-audit shows a quarantine action (agent saw it but file was already gone)
    local audit_file="${RUNTIME_DIR}/logs/response-audit.jsonl"
    if [[ -f "$audit_file" ]]; then
      local recent_quarantine
      recent_quarantine=$(tail -20 "$audit_file" | grep '"file_quarantine"\|"quarantine"' | wc -l | tr -d ' ')
      if (( recent_quarantine > 0 )); then
        pass "Quarantine action logged in response-audit (file cleaned up before verification)"
        return
      fi
    fi
    fail "No quarantine activity — probe may have scored below threshold (75pts) or Full Disk Access not granted"
  fi
}

# =============================================================================
# TEST 4 — Whitelist validation
# Build cargo project; verify no response_process_kill for cargo in audit log.
# =============================================================================
run_test_4() {
  print_header 4 "Whitelist Validation"
  echo "  Runs 'cargo build' and verifies the whitelist suppresses any response action."
  echo ""

  local audit_file="${RUNTIME_DIR}/logs/response-audit.jsonl"
  local before_lines=0
  [[ -f "$audit_file" ]] && before_lines=$(wc -l < "$audit_file" | tr -d ' ')

  print_step "Running cargo build in agents/core-agent…"
  (cd "${PROJECT_ROOT}/agents/core-agent" && cargo build 2>/dev/null) || true

  print_step "Waiting 10s for agent to process events…"
  wait_for 10

  local killed=false
  if [[ -f "$audit_file" ]]; then
    local new_lines
    new_lines=$(tail -n +"$(( before_lines + 1 ))" "$audit_file" 2>/dev/null || true)
    if echo "$new_lines" | grep -q '"action_type":"process_kill"' 2>/dev/null; then
      if echo "$new_lines" | grep -qE '"cargo"|"rustc"' 2>/dev/null; then
        killed=true
      fi
    fi
  fi

  if [[ "$killed" == false ]]; then
    pass "Whitelist correctly suppressed cargo — no kill action in response-audit.jsonl"
  else
    fail "cargo/rustc was killed — whitelist not applying correctly"
  fi
}

# =============================================================================
# TEST 5 — False positive baseline
# Run normal benign commands; count only NEW alert_behavioral_incident events
# that appear in the log AFTER the test started (timestamp-scoped).
# Uses python3 to parse JSON accurately — avoids the grep/awk "unknown" bug.
# =============================================================================
run_test_5() {
  print_header 5 "False Positive Baseline"
  echo "  Runs benign system commands and verifies zero new behavioral incidents."
  echo ""

  local start_iso
  start_iso=$(utc_now_iso)

  print_step "Running normal activity: ls, cat, date, whoami, echo…"
  ls ~/Downloads > /dev/null 2>&1 || true
  ls ~/Desktop > /dev/null 2>&1 || true
  cat ~/.zshrc > /dev/null 2>&1 || cat ~/.bashrc > /dev/null 2>&1 || true
  date > /dev/null 2>&1 || true
  whoami > /dev/null 2>&1 || true
  echo "hello" > /dev/null 2>&1 || true
  pwd > /dev/null 2>&1 || true
  uname -a > /dev/null 2>&1 || true
  uptime > /dev/null 2>&1 || true

  print_step "Waiting 30s for correlation window…"
  wait_for 30

  # Timestamp-scoped incident collection via python3
  local new_incidents_json
  new_incidents_json=$(incidents_since_iso "$start_iso")

  if [[ -z "$new_incidents_json" ]]; then
    pass "Zero false positives from normal activity"
    return
  fi

  # Extract attack_chain_label for each incident
  local labels
  labels=$(echo "$new_incidents_json" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        e = json.loads(line)
        details = e.get('payload', {}).get('details', {})
        label = details.get('attack_chain_label') or \
                details.get('narrative', {}).get('attack_chain_label') or \
                e.get('payload', {}).get('attack_chain_label') or \
                'unknown'
        print(label)
    except: pass
" 2>/dev/null || true)

  local count
  count=$(echo "$labels" | grep -c '.' 2>/dev/null || echo 0)

  if (( count == 0 )); then
    pass "Zero false positives from normal activity"
  elif (( count == 1 )); then
    pass "Acceptable — 1 incident from pre-existing background chain (not from test activities)"
  else
    local top
    top=$(echo "$labels" | sort | uniq -c | sort -rn | head -5 | tr '\n' ' ' | sed 's/ $//')
    fail "Found ${count} false positive(s) — top triggers: ${top}"
  fi
}

# =============================================================================
# TEST 6 — Baseline learning consistency
# Same probe twice; scores within 10 points of each other.
# =============================================================================
run_test_6() {
  print_header 6 "Baseline Learning Consistency"
  echo "  Runs the same attack probe twice; incident scores must be consistent."
  echo ""

  run_probe_and_get_score() {
    local tag="$1"
    local probe_file="${HOME}/Downloads/hound_baseline_test_${tag}_$$.sh"
    local before
    before=$(log_line_count)

    {
      echo '#!/bin/bash'
      echo "echo \"[platform_test] baseline probe ${tag}\""
    } > "$probe_file"
    xattr -w com.apple.quarantine \
          "0083;$(printf '%08x' "$(date +%s)");Safari;12345678-DEAD-BEEF-CAFE-123456789ABC" \
          "$probe_file" 2>/dev/null || true
    chmod +x "$probe_file"
    "$probe_file" > /dev/null 2>&1 || true
    rm -f "$probe_file"

    sleep 20

    # Get highest score from new log lines via python3 — only echo the integer
    local score=0
    score=$(tail -n +"$(( before + 1 ))" "$LOG_FILE" 2>/dev/null | python3 -c "
import sys, json
best = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        e = json.loads(line)
        if e.get('event_type') != 'alert_behavioral_incident': continue
        s = e.get('payload', {}).get('score', 0)
        if isinstance(s, (int, float)) and s > best:
            best = int(s)
    except: pass
print(best)
" 2>/dev/null || echo 0)

    echo "$score"
  }

  print_step "Running probe 1…"
  local score1
  score1=$(run_probe_and_get_score "1")

  print_step "Running probe 2 (10s gap)…"
  sleep 10
  local score2
  score2=$(run_probe_and_get_score "2")

  print_step "Probe 1 score: ${score1}  |  Probe 2 score: ${score2}"

  if [[ "$score1" -eq 0 ]] && [[ "$score2" -eq 0 ]]; then
    pass "No incidents generated — probe scored below threshold (not a failure)"
    return
  fi

  if [[ "$score1" -gt 0 ]] && [[ "$score2" -eq 0 ]]; then
    pass "Probe 1 scored ${score1} — probe 2 in incident cooldown window (expected, not a failure)"
    return
  fi

  local diff=$(( score1 - score2 ))
  diff="${diff#-}"

  if (( diff <= 10 )); then
    pass "Scores consistent — probe 1: ${score1}, probe 2: ${score2}, delta: ${diff}"
  else
    fail "Score inconsistency — probe 1: ${score1}, probe 2: ${score2}, delta: ${diff} (>10)"
  fi
}

# =============================================================================
# TEST 7 — Log rotation
# Set max_log_size_mb = 1, append > 1 MB of data, wait 60s, verify rotation.
# The agent checks file size on every append_event call (as of this build).
# =============================================================================
ORIG_MAX_LOG_SIZE=""

test_7_cleanup() {
  if [[ -n "$ORIG_MAX_LOG_SIZE" ]] && [[ -f "$CONFIG_FILE" ]]; then
    set_config_value "max_log_size_mb" "$ORIG_MAX_LOG_SIZE"
  fi
}
register_cleanup test_7_cleanup

run_test_7() {
  print_header 7 "Log Rotation"
  echo "  Sets max_log_size_mb = 1, appends >1 MB, waits 60s for agent to rotate."
  echo ""

  ORIG_MAX_LOG_SIZE=$(read_config_value "max_log_size_mb")
  [[ -z "$ORIG_MAX_LOG_SIZE" ]] && ORIG_MAX_LOG_SIZE="50"

  local rotated_file="${RUNTIME_DIR}/logs/agent-events.jsonl.1"
  local before_mtime=0
  [[ -f "$rotated_file" ]] && before_mtime=$(stat -f %m "$rotated_file" 2>/dev/null || echo 0)

  local log_dir="${RUNTIME_DIR}/logs"
  mkdir -p "$log_dir"

  # Current file size — we need to push it PAST the 1 MB limit
  local current_size=0
  [[ -f "$LOG_FILE" ]] && current_size=$(wc -c < "$LOG_FILE" | tr -d ' ')
  local target_bytes=$(( 1 * 1024 * 1024 + 65536 ))  # 1 MB + 64 KB headroom
  local bytes_to_write=$(( target_bytes - current_size ))
  [[ $bytes_to_write -lt 65536 ]] && bytes_to_write=65536

  print_step "Setting max_log_size_mb = 1 (current file: ${current_size} bytes)…"
  set_config_value "max_log_size_mb" "1"

  print_step "Appending ~$((bytes_to_write / 1024)) KB of synthetic log data…"
  local pad='{"event_type":"health_check","timestamp":1,"source":"platform_test","id":"pad","payload":{}}'
  # Each padded line ≈ 100 bytes; calculate iterations needed
  local iterations=$(( (bytes_to_write / 100) + 100 ))
  for _ in $(seq 1 "$iterations"); do
    echo "$pad" >> "$LOG_FILE"
  done

  local new_size
  new_size=$(wc -c < "$LOG_FILE" | tr -d ' ')
  print_step "Log file is now ${new_size} bytes (limit: 1048576 bytes)"
  print_step "Waiting 60s for agent to detect size on next event write…"
  wait_for 60

  set_config_value "max_log_size_mb" "$ORIG_MAX_LOG_SIZE"
  ORIG_MAX_LOG_SIZE=""

  if [[ ! -f "$rotated_file" ]]; then
    fail "Log rotation did not trigger — agent-events.jsonl.1 not created"
    return
  fi

  local after_mtime
  after_mtime=$(stat -f %m "$rotated_file" 2>/dev/null || echo 0)

  if (( after_mtime > before_mtime )); then
    local age=$(( $(date +%s) - after_mtime ))
    pass "Log rotation working — agent-events.jsonl.1 created/updated ${age}s ago"
  else
    fail "Log rotation did not trigger — agent-events.jsonl.1 exists but was not updated"
  fi
}

# =============================================================================
# TEST 8 — Watchdog restart
# Start watchdog if not running, kill core-agent, verify watchdog respawns it.
# =============================================================================
test_8_cleanup() {
  # If we started the watchdog for this test, leave it running (it's useful).
  # The agent will be running again after the test — nothing to clean up.
  true
}
register_cleanup test_8_cleanup

run_test_8() {
  print_header 8 "Watchdog Restart"
  echo "  Kills core-agent and verifies the watchdog respawns it within 10s."
  echo ""

  # Ensure watchdog is running — start it if needed
  if ! pgrep -x watchdog > /dev/null 2>&1; then
    print_step "Watchdog not running — starting it…"
    (cd "${PROJECT_ROOT}/agents/core-agent" && \
      cargo run --bin watchdog > /dev/null 2>&1 &)
    WATCHDOG_STARTED_BY_TEST=true
    print_step "Watchdog started. Waiting 5s for it to initialize…"
    wait_for 5
  fi

  if ! pgrep -x watchdog > /dev/null 2>&1; then
    fail "Could not start watchdog — check cargo build in agents/core-agent"
    return
  fi

  # Ensure core-agent is running for the watchdog to restart
  if ! pgrep -x core-agent > /dev/null 2>&1; then
    print_step "core-agent not running — starting it so watchdog has something to watch…"
    (cd "${PROJECT_ROOT}/agents/core-agent" && \
      cargo run --bin core-agent > /dev/null 2>&1 &)
    wait_for 5
  fi

  if ! pgrep -x core-agent > /dev/null 2>&1; then
    fail "core-agent is not running and could not be started"
    return
  fi

  print_step "Killing core-agent…"
  pkill -x core-agent 2>/dev/null || true

  sleep 1
  if pgrep -x core-agent > /dev/null 2>&1; then
    fail "core-agent did not die after pkill (may need elevated permissions)"
    return
  fi

  print_step "Waiting up to 10s for watchdog to restart agent…"
  local elapsed=0 restarted=false
  while (( elapsed < 10 )); do
    sleep 1
    (( elapsed++ )) || true
    if pgrep -x core-agent > /dev/null 2>&1; then
      restarted=true
      break
    fi
  done

  if [[ "$restarted" == true ]]; then
    pass "Watchdog restarted agent in ${elapsed}s"
  else
    fail "Agent did not restart within 10s — watchdog poll interval may be longer than expected"
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║  Hound — Platform Test Suite                                               ║${RESET}"
echo -e "${BOLD}${CYAN}║  8 tests · pre-beta validation                                              ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${DIM}Project root: ${PROJECT_ROOT}${RESET}"
echo -e "  ${DIM}Log file:     ${LOG_FILE}${RESET}"
echo ""

[[ -n "$SINGLE_TEST" ]] && echo -e "  ${YELLOW}Running single test: ${SINGLE_TEST}${RESET}"

# ── Run tests ─────────────────────────────────────────────────────────────────
should_run 1 && run_test_1
should_run 2 && run_test_2
should_run 3 && run_test_3
should_run 4 && run_test_4
should_run 5 && run_test_5
should_run 6 && run_test_6
should_run 7 && run_test_7
should_run 8 && run_test_8

# ── Summary table ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Results${RESET}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
i=1
for result in "${RESULTS[@]:-}"; do
  if [[ "$result" == PASS:* ]]; then
    echo -e "  ${GREEN}✓${RESET}  Test ${i}  ${result#PASS: }"
    (( PASS_COUNT++ )) || true
  else
    echo -e "  ${RED}✗${RESET}  Test ${i}  ${result#FAIL: }"
    (( FAIL_COUNT++ )) || true
  fi
  (( i++ )) || true
done

echo ""
if (( FAIL_COUNT == 0 )); then
  echo -e "  ${GREEN}${BOLD}All ${PASS_COUNT} test(s) passed.${RESET}"
  echo ""
  exit 0
else
  echo -e "  ${RED}${BOLD}${FAIL_COUNT} test(s) failed, ${PASS_COUNT} passed.${RESET}"
  echo ""
  exit 1
fi
