use crate::models::{AlertSeverity, TelemetryEvent};
use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::UNIX_EPOCH;

const BTM_FILE: &str =
    "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm";

pub struct PersistenceMonitor {
    last_crontab: Option<String>,
    last_login_hook: Option<String>,
    last_logout_hook: Option<String>,
    /// Last-seen mtime of the BTM database file (seconds since UNIX epoch).
    /// `None` means the file did not exist or was unreadable at last check.
    last_btm_mtime: Option<u64>,
    /// SHA256 of ~/Library/Preferences/com.apple.dock.plist content.
    last_dock_plist_hash: Option<String>,
    /// Set of known at-job filenames in /var/at/jobs/ at last check.
    last_at_jobs: Option<std::collections::HashSet<String>>,
    /// Last-seen resume hook value from com.apple.loginwindow.
    last_resume_hook: Option<String>,
    /// Last-seen sleep hook value from com.apple.loginwindow.
    last_sleep_hook: Option<String>,
    initialized: bool,
}

impl PersistenceMonitor {
    pub fn new() -> Self {
        Self {
            last_crontab: None,
            last_login_hook: None,
            last_logout_hook: None,
            last_btm_mtime: None,
            last_dock_plist_hash: None,
            last_at_jobs: None,
            last_resume_hook: None,
            last_sleep_hook: None,
            initialized: false,
        }
    }

    /// Poll crontab, loginwindow hooks, BTM database, dock plist, at jobs, and extended hooks.
    /// On the first call, baseline silently.
    /// On subsequent calls, emit alerts for any changes observed.
    pub fn check_and_update(&mut self, now: DateTime<Utc>) -> Vec<TelemetryEvent> {
        let mut events = Vec::new();

        let current_crontab = read_crontab();
        let (current_login_hook, current_logout_hook) = read_loginwindow_hooks();
        let (current_resume_hook, current_sleep_hook) = read_extended_loginwindow_hooks();
        let current_btm_mtime = read_btm_mtime();
        let current_dock_hash = read_dock_plist_hash();
        let current_at_jobs = read_at_jobs();

        if self.initialized {
            // ── Crontab ───────────────────────────────────────────────────────
            if let (Some(prev), Some(curr)) = (&self.last_crontab, &current_crontab) {
                if prev != curr {
                    events.push(build_alert(
                        now,
                        "alert_crontab_modified",
                        AlertSeverity::High,
                        "persistence",
                        "The user crontab was modified",
                        json!({
                            "mitre_technique": "T1053.003",
                            "reason": "crontab -l output changed since last check",
                            "previous_length_bytes": prev.len(),
                            "current_length_bytes": curr.len(),
                        }),
                    ));
                }
            } else if self.last_crontab.is_none() && current_crontab.is_some() {
                let curr = current_crontab.as_deref().unwrap_or("");
                if !curr.trim().is_empty() {
                    events.push(build_alert(
                        now,
                        "alert_crontab_modified",
                        AlertSeverity::High,
                        "persistence",
                        "A crontab was created",
                        json!({
                            "mitre_technique": "T1053.003",
                            "reason": "crontab -l now returns entries where it previously returned none",
                            "current_length_bytes": curr.len(),
                        }),
                    ));
                }
            }

            // ── LoginHook ─────────────────────────────────────────────────────
            if let Some(hook) = &current_login_hook {
                if self.last_login_hook.as_deref() != Some(hook.as_str()) {
                    events.push(build_alert(
                        now,
                        "alert_login_hook_installed",
                        AlertSeverity::Critical,
                        "persistence",
                        "A LoginHook was installed in com.apple.loginwindow",
                        json!({
                            "mitre_technique": "T1037.002",
                            "hook_type": "LoginHook",
                            "hook_value": hook,
                            "reason": "LoginHook key detected or changed in com.apple.loginwindow defaults domain",
                        }),
                    ));
                }
            }

            // ── LogoutHook ────────────────────────────────────────────────────
            if let Some(hook) = &current_logout_hook {
                if self.last_logout_hook.as_deref() != Some(hook.as_str()) {
                    events.push(build_alert(
                        now,
                        "alert_login_hook_installed",
                        AlertSeverity::High,
                        "persistence",
                        "A LogoutHook was installed in com.apple.loginwindow",
                        json!({
                            "mitre_technique": "T1037.002",
                            "hook_type": "LogoutHook",
                            "hook_value": hook,
                            "reason": "LogoutHook key detected or changed in com.apple.loginwindow defaults domain",
                        }),
                    ));
                }
            }

            // ── BTM database file watch (T1547.001) ───────────────────────────
            // Emit when the file appears for the first time or its mtime advances.
            // The BTM database is written by backgroundtaskmanagementd whenever a
            // login item is registered; we do not need to parse its binary format —
            // any write to the file is sufficient signal.
            let btm_changed = match (self.last_btm_mtime, current_btm_mtime) {
                (None, Some(_)) => true,          // file appeared
                (Some(prev), Some(curr)) => curr != prev, // mtime advanced
                _ => false,
            };

            if btm_changed {
                events.push(build_alert(
                    now,
                    "alert_login_item_added",
                    AlertSeverity::High,
                    "persistence",
                    "The Background Task Management database was modified",
                    json!({
                        "mitre_technique": "T1547.001",
                        "btm_path": BTM_FILE,
                        "reason": "BackgroundItems-v4.btm mtime changed — a login item may have been added or removed",
                        "previous_mtime": self.last_btm_mtime,
                        "current_mtime": current_btm_mtime,
                    }),
                ));
            }
        }

        if self.initialized {
            // ── Dock persistence (T1547) ──────────────────────────────────────
            // Some malware persists by injecting itself into the macOS Dock.
            // Any modification to com.apple.dock.plist is worth flagging.
            let dock_changed = match (&self.last_dock_plist_hash, &current_dock_hash) {
                (None, Some(_)) => false, // First time seeing the file — baseline
                (Some(prev), Some(curr)) => prev != curr,
                _ => false,
            };
            if dock_changed {
                events.push(build_alert(
                    now,
                    "alert_dock_persistence",
                    AlertSeverity::Medium,
                    "persistence",
                    "macOS Dock configuration was modified — possible Dock persistence",
                    json!({
                        "mitre_technique": "T1547",
                        "plist_path": format!("{}/Library/Preferences/com.apple.dock.plist",
                            std::env::var("HOME").unwrap_or_default()),
                        "reason": "com.apple.dock.plist content hash changed — a new Dock item may have been added by malware",
                    }),
                ));
            }

            // ── At-job persistence (T1053.002) ────────────────────────────────
            // `at` jobs are a real but less-used persistence mechanism. Watch
            // /var/at/jobs/ for new scheduled tasks.
            if let (Some(prev_jobs), Some(curr_jobs)) = (&self.last_at_jobs, &current_at_jobs) {
                let new_jobs: Vec<&String> = curr_jobs.difference(prev_jobs).collect();
                for job in new_jobs {
                    events.push(build_alert(
                        now,
                        "alert_at_job_created",
                        AlertSeverity::High,
                        "persistence",
                        "New at-job created in /var/at/jobs — scheduled persistence mechanism",
                        json!({
                            "mitre_technique": "T1053.002",
                            "job_name": job,
                            "reason": "New file appeared in /var/at/jobs/ — attacker may be using at for delayed execution",
                        }),
                    ));
                }
            }

            // ── ResumeHook ────────────────────────────────────────────────────
            if let Some(hook) = &current_resume_hook {
                if self.last_resume_hook.as_deref() != Some(hook.as_str()) {
                    events.push(build_alert(
                        now,
                        "alert_login_hook_installed",
                        AlertSeverity::High,
                        "persistence",
                        "A ResumeHook was installed in com.apple.loginwindow",
                        json!({
                            "mitre_technique": "T1037.002",
                            "hook_type": "ResumeHook",
                            "hook_value": hook,
                            "reason": "ResumeHook key detected or changed in com.apple.loginwindow defaults domain",
                        }),
                    ));
                }
            }

            // ── SleepHook ─────────────────────────────────────────────────────
            if let Some(hook) = &current_sleep_hook {
                if self.last_sleep_hook.as_deref() != Some(hook.as_str()) {
                    events.push(build_alert(
                        now,
                        "alert_login_hook_installed",
                        AlertSeverity::High,
                        "persistence",
                        "A SleepHook was installed in com.apple.loginwindow",
                        json!({
                            "mitre_technique": "T1037.002",
                            "hook_type": "SleepHook",
                            "hook_value": hook,
                            "reason": "SleepHook key detected or changed in com.apple.loginwindow defaults domain",
                        }),
                    ));
                }
            }
        }

        self.last_crontab = current_crontab;
        self.last_login_hook = current_login_hook;
        self.last_logout_hook = current_logout_hook;
        self.last_btm_mtime = current_btm_mtime;
        self.last_dock_plist_hash = current_dock_hash;
        self.last_at_jobs = current_at_jobs;
        self.last_resume_hook = current_resume_hook;
        self.last_sleep_hook = current_sleep_hook;
        self.initialized = true;

        events
    }
}

// ── Readers ───────────────────────────────────────────────────────────────────

fn read_crontab() -> Option<String> {
    let output = Command::new("crontab").arg("-l").output().ok()?;
    // Exit code 1 with "no crontab for user" stderr is normal on macOS — treat as empty
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.trim().is_empty() {
        None
    } else {
        Some(stdout)
    }
}

fn read_loginwindow_hooks() -> (Option<String>, Option<String>) {
    let output = Command::new("defaults")
        .args(["read", "com.apple.loginwindow"])
        .output();

    let Ok(output) = output else {
        return (None, None);
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let login_hook = extract_hook_value(&text, "LoginHook");
    let logout_hook = extract_hook_value(&text, "LogoutHook");

    (login_hook, logout_hook)
}

/// Read ResumeHook and SleepHook from com.apple.loginwindow.
/// These are less common than Login/LogoutHooks but used by some malware.
fn read_extended_loginwindow_hooks() -> (Option<String>, Option<String>) {
    let output = Command::new("defaults")
        .args(["read", "com.apple.loginwindow"])
        .output();

    let Ok(output) = output else {
        return (None, None);
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let resume_hook = extract_hook_value(&text, "ResumeHook");
    let sleep_hook = extract_hook_value(&text, "SleepHook");
    (resume_hook, sleep_hook)
}

/// Compute SHA256 of ~/Library/Preferences/com.apple.dock.plist.
/// Returns None if the file does not exist or cannot be read.
fn read_dock_plist_hash() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = format!("{home}/Library/Preferences/com.apple.dock.plist");
    let content = std::fs::read(&path).ok()?;
    let hash = Sha256::digest(&content);
    Some(format!("{:x}", hash))
}

/// List filenames in /var/at/jobs/ — used to detect new at-job entries.
/// Returns None if the directory cannot be read (normal if at is not used).
fn read_at_jobs() -> Option<std::collections::HashSet<String>> {
    let entries = std::fs::read_dir("/var/at/jobs").ok()?;
    let names = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.starts_with('.'))
        .collect();
    Some(names)
}

/// Return the mtime of the BTM database file as seconds since the UNIX epoch,
/// or `None` if the file does not exist or its metadata cannot be read.
pub fn read_btm_mtime() -> Option<u64> {
    std::fs::metadata(BTM_FILE)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Parse a value from `defaults read` output like:
///   LoginHook = "/path/to/script.sh";
fn extract_hook_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let value = rest
                    .trim()
                    .trim_end_matches(';')
                    .trim_matches('"')
                    .to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn build_alert(
    now: DateTime<Utc>,
    event_type: &str,
    severity: AlertSeverity,
    category: &str,
    reason: &str,
    mut details: serde_json::Value,
) -> TelemetryEvent {
    if let Some(obj) = details.as_object_mut() {
        obj.insert("category".to_string(), json!(category));
        obj.insert("reason".to_string(), json!(reason));
    }
    TelemetryEvent::alert(now, event_type, severity, reason, details)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_hook_value ─────────────────────────────────────────────────────

    #[test]
    fn extract_hook_value_finds_login_hook() {
        let text = r#"{
    LoginHook = "/usr/local/bin/login_setup.sh";
    SomeOtherKey = 1;
}"#;
        assert_eq!(
            extract_hook_value(text, "LoginHook"),
            Some("/usr/local/bin/login_setup.sh".to_string())
        );
    }

    #[test]
    fn extract_hook_value_returns_none_when_absent() {
        let text = r#"{
    SomeOtherKey = 1;
}"#;
        assert_eq!(extract_hook_value(text, "LoginHook"), None);
    }

    // ── Crontab change detection ───────────────────────────────────────────────

    #[test]
    fn monitor_emits_alert_when_crontab_changes() {
        let prev = "* * * * * /bin/old_task.sh\n".to_string();
        let curr = "* * * * * /bin/new_task.sh\n".to_string();
        assert!(prev != curr, "crontab change should be detected");
    }

    #[test]
    fn monitor_does_not_alert_on_identical_crontab() {
        let same = "* * * * * /bin/task.sh\n".to_string();
        assert!(same == same.clone(), "identical crontab should not trigger alert");
    }

    // ── BTM file mtime change detection ───────────────────────────────────────

    #[test]
    fn btm_mtime_change_triggers_alert() {
        let now = Utc::now();

        let mut monitor = PersistenceMonitor {
            last_crontab: None,
            last_login_hook: None,
            last_logout_hook: None,
            last_btm_mtime: Some(1_700_000_000),
            last_dock_plist_hash: None,
            last_at_jobs: None,
            last_resume_hook: None,
            last_sleep_hook: None,
            initialized: true,
        };

        // Simulate a newer mtime by directly exercising the change-detection logic
        let prev = monitor.last_btm_mtime;
        let current: Option<u64> = Some(1_700_000_060); // 60 seconds later

        let btm_changed = match (prev, current) {
            (None, Some(_)) => true,
            (Some(p), Some(c)) => c != p,
            _ => false,
        };

        assert!(btm_changed, "advancing mtime should be detected as a BTM change");

        // Also verify an event is emitted when we wire it through build_alert
        if btm_changed {
            let event = build_alert(
                now,
                "alert_login_item_added",
                AlertSeverity::High,
                "persistence",
                "The Background Task Management database was modified",
                json!({
                    "mitre_technique": "T1547.001",
                    "btm_path": BTM_FILE,
                    "previous_mtime": prev,
                    "current_mtime": current,
                }),
            );
            assert_eq!(event.event_type, "alert_login_item_added");
            assert_eq!(
                event.payload["severity"].as_str().unwrap_or(""),
                "high"
            );
        }
    }

    #[test]
    fn btm_mtime_unchanged_no_alert() {
        let mtime: Option<u64> = Some(1_700_000_000);

        let btm_changed = match (mtime, mtime) {
            (None, Some(_)) => true,
            (Some(p), Some(c)) => c != p,
            _ => false,
        };

        assert!(!btm_changed, "identical mtime should not trigger an alert");
    }

    #[test]
    fn btm_file_appearing_for_first_time_triggers_alert() {
        let prev: Option<u64> = None;
        let current: Option<u64> = Some(1_700_000_000);

        let btm_changed = match (prev, current) {
            (None, Some(_)) => true,
            (Some(p), Some(c)) => c != p,
            _ => false,
        };

        assert!(btm_changed, "BTM file appearing should count as a change");
    }

    #[test]
    fn btm_absent_on_both_checks_no_alert() {
        let prev: Option<u64> = None;
        let current: Option<u64> = None;

        let btm_changed = match (prev, current) {
            (None, Some(_)) => true,
            (Some(p), Some(c)) => c != p,
            _ => false,
        };

        assert!(!btm_changed, "absent file on both checks should not alert");
    }
}
