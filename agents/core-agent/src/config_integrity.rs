/// Config integrity and runtime directory protection.
///
/// This module:
///   1. Hashes `runtime/policy.json` at startup and periodically re-checks for tampering.
///   2. Ensures `runtime/logs/` and `runtime/quarantine/` have owner-only (0o700) permissions.
///   3. Maintains a tamper-evident SHA256 chain for `runtime/logs/agent-events.jsonl`.
///
/// Any discrepancy is surfaced as a `TelemetryEvent` with type `alert_config_tampered` or
/// `alert_log_tampered` so the incident correlation engine can correlate it with other
/// defense-evasion signals.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const POLICY_PATH: &str = "runtime/policy.json";
const HASH_STORE_PATH: &str = "runtime/.integrity";
const EVENT_LOG_PATH: &str = "runtime/logs/agent-events.jsonl";

/// Persisted integrity state, written to `runtime/.integrity` as JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct IntegrityState {
    /// SHA256 hex digest of policy.json at last check.
    pub policy_hash: Option<String>,
    /// Number of lines in agent-events.jsonl at last manifest update.
    pub event_log_line_count: u64,
    /// SHA256 hex digest of the last line written to agent-events.jsonl.
    pub event_log_last_line_hash: Option<String>,
}

impl IntegrityState {
    /// Load from disk, or return a default (blank) state.
    pub fn load() -> Self {
        let path = Path::new(HASH_STORE_PATH);
        if !path.exists() {
            return Self::default();
        }
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist to disk.  Errors are non-fatal (silently ignored — missing store ≠ tamper).
    pub fn save(&self) {
        if let Ok(serialized) = serde_json::to_string_pretty(self) {
            let _ = fs::write(HASH_STORE_PATH, serialized);
        }
    }
}

/// Called once at startup.  Returns `(state, tamper_events)`.
///
/// * Loads persisted integrity state.
/// * If `runtime/policy.json` exists and a stored hash exists, verifies it.
/// * Re-hashes the current policy and stores the result.
/// * Checks runtime directory permissions.
pub fn startup_check() -> (IntegrityState, Vec<TamperEvent>) {
    let mut events = Vec::new();
    let mut state = IntegrityState::load();

    // ── Policy file integrity ─────────────────────────────────────────────────
    let policy_path = Path::new(POLICY_PATH);
    if policy_path.exists() {
        match sha256_file(policy_path) {
            Ok(current_hash) => {
                if let Some(stored) = &state.policy_hash {
                    if *stored != current_hash {
                        events.push(TamperEvent {
                            kind: TamperKind::ConfigTampered,
                            detail: format!(
                                "runtime/policy.json hash mismatch: stored={} actual={}",
                                &stored[..8],
                                &current_hash[..8]
                            ),
                        });
                    }
                }
                state.policy_hash = Some(current_hash);
            }
            Err(e) => {
                events.push(TamperEvent {
                    kind: TamperKind::ConfigTampered,
                    detail: format!("failed to hash runtime/policy.json: {e}"),
                });
            }
        }
    }

    // ── Event log integrity ───────────────────────────────────────────────────
    let log_path = Path::new(EVENT_LOG_PATH);
    if log_path.exists() {
        match count_lines_and_last_hash(log_path) {
            Ok((line_count, last_hash)) => {
                if state.event_log_line_count > 0 && line_count < state.event_log_line_count {
                    events.push(TamperEvent {
                        kind: TamperKind::LogTampered,
                        detail: format!(
                            "agent-events.jsonl truncated: expected ≥{} lines, found {}",
                            state.event_log_line_count, line_count
                        ),
                    });
                }
                if let (Some(stored_last), Some(current_last)) = (&state.event_log_last_line_hash, &last_hash) {
                    // Only flag if line count matches exactly (same terminal line was modified).
                    if line_count == state.event_log_line_count && stored_last != current_last {
                        events.push(TamperEvent {
                            kind: TamperKind::LogTampered,
                            detail: format!(
                                "agent-events.jsonl last-line hash mismatch: stored={} actual={}",
                                &stored_last[..8],
                                &current_last[..8]
                            ),
                        });
                    }
                }
                state.event_log_line_count = line_count;
                state.event_log_last_line_hash = last_hash;
            }
            Err(e) => {
                events.push(TamperEvent {
                    kind: TamperKind::LogTampered,
                    detail: format!("failed to inspect agent-events.jsonl: {e}"),
                });
            }
        }
    }

    // ── Runtime directory permissions ─────────────────────────────────────────
    for dir in &["runtime/logs", "runtime/quarantine"] {
        let p = Path::new(dir);
        if p.exists() {
            match enforce_owner_only(p) {
                Ok(fixed) if fixed => {
                    events.push(TamperEvent {
                        kind: TamperKind::DirPermissionFixed,
                        detail: format!("{dir} had world-readable permissions — corrected to 0o700"),
                    });
                }
                Err(e) => {
                    events.push(TamperEvent {
                        kind: TamperKind::DirPermissionFixed,
                        detail: format!("failed to enforce permissions on {dir}: {e}"),
                    });
                }
                _ => {}
            }
        }
    }

    state.save();
    (state, events)
}

/// Periodic check — call every N main-loop iterations.
/// Re-hashes `runtime/policy.json` and compares to `state.policy_hash`.
/// Returns tamper events (if any) and updates `state` in place.
pub fn periodic_check(state: &mut IntegrityState) -> Vec<TamperEvent> {
    let mut events = Vec::new();
    let policy_path = Path::new(POLICY_PATH);

    if !policy_path.exists() {
        return events;
    }

    match sha256_file(policy_path) {
        Ok(current_hash) => {
            if let Some(stored) = &state.policy_hash {
                if *stored != current_hash {
                    events.push(TamperEvent {
                        kind: TamperKind::ConfigTampered,
                        detail: format!(
                            "runtime/policy.json modified at runtime: stored={} actual={}",
                            &stored[..8],
                            &current_hash[..8]
                        ),
                    });
                    // Update so we don't fire every loop after a change.
                    state.policy_hash = Some(current_hash);
                    state.save();
                }
            } else {
                state.policy_hash = Some(current_hash);
                state.save();
            }
        }
        Err(e) => {
            events.push(TamperEvent {
                kind: TamperKind::ConfigTampered,
                detail: format!("failed to hash runtime/policy.json during periodic check: {e}"),
            });
        }
    }

    events
}

/// Called after appending a new event to the log.  Updates the manifest snapshot.
pub fn update_log_manifest(state: &mut IntegrityState) {
    let log_path = Path::new(EVENT_LOG_PATH);
    if !log_path.exists() {
        return;
    }
    if let Ok((line_count, last_hash)) = count_lines_and_last_hash(log_path) {
        state.event_log_line_count = line_count;
        state.event_log_last_line_hash = last_hash;
        state.save();
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Count lines in a file and return the SHA256 of the last non-empty line.
fn count_lines_and_last_hash(path: &Path) -> Result<(u64, Option<String>)> {
    let content = fs::read_to_string(path)?;
    let mut count: u64 = 0;
    let mut last_line_hash: Option<String> = None;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
        last_line_hash = Some(sha256_bytes(line.as_bytes()));
    }
    Ok((count, last_line_hash))
}

/// Ensure a directory is owner-only (mode 0o700).  Returns `true` if permissions were corrected.
fn enforce_owner_only(path: &Path) -> Result<bool> {
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(path, perms)?;
        return Ok(true);
    }
    Ok(false)
}

/// A detected tamper event (pre-TelemetryEvent, converted by main.rs).
#[derive(Debug)]
pub struct TamperEvent {
    pub kind: TamperKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperKind {
    ConfigTampered,
    LogTampered,
    DirPermissionFixed,
}

impl TamperKind {
    pub fn as_event_type(&self) -> &'static str {
        match self {
            TamperKind::ConfigTampered => "alert_config_tampered",
            TamperKind::LogTampered => "alert_log_tampered",
            TamperKind::DirPermissionFixed => "alert_dir_permission_corrected",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            TamperKind::ConfigTampered => "high",
            TamperKind::LogTampered => "high",
            TamperKind::DirPermissionFixed => "medium",
        }
    }
}
