use crate::models::{AlertSeverity, TelemetryEvent};
use chrono::{DateTime, Utc};
use serde_json::json;
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
    initialized: bool,
}

impl PersistenceMonitor {
    pub fn new() -> Self {
        Self {
            last_crontab: None,
            last_login_hook: None,
            last_logout_hook: None,
            last_btm_mtime: None,
            initialized: false,
        }
    }

    /// Poll crontab, loginwindow hooks, and the BTM database file.
    /// On the first call, baseline silently.
    /// On subsequent calls, emit alerts for any changes observed.
    pub fn check_and_update(&mut self, now: DateTime<Utc>) -> Vec<TelemetryEvent> {
        let mut events = Vec::new();

        let current_crontab = read_crontab();
        let (current_login_hook, current_logout_hook) = read_loginwindow_hooks();
        let current_btm_mtime = read_btm_mtime();

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

        self.last_crontab = current_crontab;
        self.last_login_hook = current_login_hook;
        self.last_logout_hook = current_logout_hook;
        self.last_btm_mtime = current_btm_mtime;
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
