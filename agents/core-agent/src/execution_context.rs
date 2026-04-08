// Classifies where a process originated — Claude Code, Cursor, npm install, terminal, etc.
// Used by the scope violation detector to evaluate whether an execution exceeded its scope.

use chrono::{DateTime, Utc};
use crate::models::ProcessInfo;

/// Known safe hosts for development work. Connections to these hosts from developer
/// tools are expected and do not constitute scope violations.
pub const KNOWN_DEV_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "github.com",
    "githubusercontent.com",
    "api.github.com",
    "gitlab.com",
    "bitbucket.org",
    "pkg.go.dev",
    "sum.golang.org",
    "rubygems.org",
    "dl.google.com",
    "storage.googleapis.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "api.anthropic.com",
    "api.openai.com",
    "api.cursor.sh",
    "update.electronjs.org",
    "formulae.brew.sh",
    "homebrew.bintray.com",
];

/// Hosts that npm specifically connects to for package downloads.
pub const NPM_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "github.com",
    "githubusercontent.com",
];

/// What behaviors an execution source is expected to perform.
/// Violations of these expectations trigger scope violation alerts.
#[derive(Debug, Clone)]
pub struct ExpectedBehaviors {
    pub may_write_files: bool,
    pub may_run_builds: bool,
    pub may_install_packages: bool,
    pub may_access_network: bool,
    pub allowed_network_hosts: Vec<&'static str>,
    pub may_access_credentials: bool,
    pub may_install_persistence: bool,
    pub may_escalate_privileges: bool,
}

impl ExpectedBehaviors {
    /// Fully permissive — no scope violations possible. Used as fallback.
    pub fn permissive() -> Self {
        ExpectedBehaviors {
            may_write_files: true,
            may_run_builds: true,
            may_install_packages: true,
            may_access_network: true,
            allowed_network_hosts: KNOWN_DEV_HOSTS.to_vec(),
            may_access_credentials: true,
            may_install_persistence: true,
            may_escalate_privileges: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionSource {
    ClaudeCode,      // Claude Code AI coding tool
    Cursor,          // Cursor AI editor
    Codex,           // OpenAI Codex / Copilot
    NpmInstall,      // npm install and post-install scripts
    PipInstall,      // pip install
    CargoInstall,    // cargo install
    Terminal,        // Direct interactive terminal session
    VscodeTerminal,  // VS Code integrated terminal
    Script,          // Non-interactive script execution
    Unknown,
}

impl ExecutionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionSource::ClaudeCode => "claude_code",
            ExecutionSource::Cursor => "cursor",
            ExecutionSource::Codex => "codex",
            ExecutionSource::NpmInstall => "npm_install",
            ExecutionSource::PipInstall => "pip_install",
            ExecutionSource::CargoInstall => "cargo_install",
            ExecutionSource::Terminal => "terminal",
            ExecutionSource::VscodeTerminal => "vscode_terminal",
            ExecutionSource::Script => "script",
            ExecutionSource::Unknown => "unknown",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ExecutionSource::ClaudeCode => "Claude Code",
            ExecutionSource::Cursor => "Cursor",
            ExecutionSource::Codex => "Codex",
            ExecutionSource::NpmInstall => "npm install",
            ExecutionSource::PipInstall => "pip install",
            ExecutionSource::CargoInstall => "cargo install",
            ExecutionSource::Terminal => "Terminal",
            ExecutionSource::VscodeTerminal => "VS Code Terminal",
            ExecutionSource::Script => "Script",
            ExecutionSource::Unknown => "Unknown",
        }
    }

    /// Returns the behaviors this execution source is expected to perform.
    /// Anything outside these behaviors is a scope violation.
    pub fn expected_behaviors(&self) -> ExpectedBehaviors {
        match self {
            // Claude Code: can write files, run builds, install packages, access dev network
            // Should NOT access credentials, install LaunchAgents, or escalate privileges
            ExecutionSource::ClaudeCode => ExpectedBehaviors {
                may_write_files: true,
                may_run_builds: true,
                may_install_packages: true,
                may_access_network: true,
                allowed_network_hosts: KNOWN_DEV_HOSTS.to_vec(),
                may_access_credentials: false,
                may_install_persistence: false,
                may_escalate_privileges: false,
            },
            // Cursor: same as Claude Code
            ExecutionSource::Cursor => ExpectedBehaviors {
                may_write_files: true,
                may_run_builds: true,
                may_install_packages: true,
                may_access_network: true,
                allowed_network_hosts: KNOWN_DEV_HOSTS.to_vec(),
                may_access_credentials: false,
                may_install_persistence: false,
                may_escalate_privileges: false,
            },
            // npm install: downloads packages and runs post-install scripts
            // Post-install scripts have limited legitimate scope
            ExecutionSource::NpmInstall => ExpectedBehaviors {
                may_write_files: true,
                may_run_builds: true,
                may_install_packages: false,
                may_access_network: true,
                allowed_network_hosts: NPM_HOSTS.to_vec(),
                may_access_credentials: false,
                may_install_persistence: false,
                may_escalate_privileges: false,
            },
            // pip install: similar to npm
            ExecutionSource::PipInstall => ExpectedBehaviors {
                may_write_files: true,
                may_run_builds: true,
                may_install_packages: false,
                may_access_network: true,
                allowed_network_hosts: vec![
                    "pypi.org", "files.pythonhosted.org", "github.com", "githubusercontent.com",
                ],
                may_access_credentials: false,
                may_install_persistence: false,
                may_escalate_privileges: false,
            },
            // cargo install: trusted for development, broader network access
            ExecutionSource::CargoInstall => ExpectedBehaviors {
                may_write_files: true,
                may_run_builds: true,
                may_install_packages: false,
                may_access_network: true,
                allowed_network_hosts: vec![
                    "crates.io", "static.crates.io", "github.com", "githubusercontent.com",
                ],
                may_access_credentials: false,
                may_install_persistence: false,
                may_escalate_privileges: false,
            },
            // Terminal and VS Code Terminal: user is interactively in control
            // Flag credential access and persistence but otherwise permissive
            ExecutionSource::Terminal | ExecutionSource::VscodeTerminal => ExpectedBehaviors {
                may_write_files: true,
                may_run_builds: true,
                may_install_packages: true,
                may_access_network: true,
                allowed_network_hosts: KNOWN_DEV_HOSTS.to_vec(),
                may_access_credentials: false,
                may_install_persistence: false,
                may_escalate_privileges: false,
            },
            // Everything else: fully permissive (don't have enough context)
            _ => ExpectedBehaviors::permissive(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub pid: i32,
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub args: String,
    pub source: ExecutionSource,
    pub parent_command: String,
}

impl ExecutionContext {
    pub fn from_process(process: &ProcessInfo, now: DateTime<Utc>) -> Self {
        let parent_command = process.parent_command.clone().unwrap_or_default();
        let source = detect_execution_source(process);
        ExecutionContext {
            pid: process.pid,
            timestamp: now,
            command: process.command.clone(),
            args: process.args.clone(),
            source,
            parent_command,
        }
    }
}

/// Classifies what spawned a process chain by walking up the parent tree.
pub fn detect_execution_source(process: &ProcessInfo) -> ExecutionSource {
    let cmd_lower = process.command.to_lowercase();
    let args_lower = process.args.to_lowercase();
    let parent = process.parent_command.as_deref().unwrap_or("").to_lowercase();
    let parent_basename = parent.rsplit('/').next().unwrap_or(&parent);

    // CI/CD environment detection via well-known env vars
    if std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("CIRCLECI").is_ok()
        || std::env::var("JENKINS_HOME").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("BUILDKITE").is_ok()
    {
        return ExecutionSource::Script;
    }

    // Claude Code: node process with .claude in path, or parent named claude
    if cmd_lower.contains("claude")
        || parent.contains("claude")
        || args_lower.contains(".claude")
        || args_lower.contains("claude-code")
    {
        return ExecutionSource::ClaudeCode;
    }

    // Cursor AI editor
    if cmd_lower.contains("cursor") || parent.contains("cursor") {
        return ExecutionSource::Cursor;
    }

    // Codex / GitHub Copilot
    if cmd_lower.contains("codex") || parent.contains("copilot") || parent.contains("codex") {
        return ExecutionSource::Codex;
    }

    // Package managers — the install command itself
    let cmd_basename = cmd_lower.rsplit('/').next().unwrap_or(&cmd_lower);
    if (cmd_basename == "npm" || cmd_basename == "npx") && args_lower.contains("install") {
        return ExecutionSource::NpmInstall;
    }
    if (cmd_basename == "pip" || cmd_basename == "pip3") && args_lower.contains("install") {
        return ExecutionSource::PipInstall;
    }
    if cmd_basename == "cargo" && args_lower.contains("install") {
        return ExecutionSource::CargoInstall;
    }

    // VS Code terminal
    if parent.contains("electron") && (parent.contains("vscode") || parent.contains("code")) {
        return ExecutionSource::VscodeTerminal;
    }
    if parent_basename == "code" || parent.contains("/vscode/") {
        return ExecutionSource::VscodeTerminal;
    }

    // Terminal emulator detection
    let terminal_emulators = [
        "iterm2", "terminal", "alacritty", "warp", "hyper", "kitty", "wezterm",
    ];
    if terminal_emulators.iter().any(|&t| parent_basename.contains(t)) {
        return ExecutionSource::Terminal;
    }

    // Shell detection — distinguish interactive vs script
    let shells = ["zsh", "bash", "fish", "sh", "dash", "tcsh", "ksh"];
    if shells.iter().any(|&s| parent_basename == s) {
        let parent_args = process.parent_args.as_deref().unwrap_or("");
        if parent_args.contains("-i") || parent_args.is_empty() {
            return ExecutionSource::Terminal;
        }
        return ExecutionSource::Script;
    }

    // Script execution via interpreter
    let interpreters = ["python", "python3", "ruby", "perl", "node", "deno", "bun"];
    if interpreters.iter().any(|&interp| parent_basename.starts_with(interp)) {
        return ExecutionSource::Script;
    }

    ExecutionSource::Unknown
}

/// Tracks executions seen in the current agent session.
pub struct ExecutionTracker {
    pub total_executions: u64,
    pub scope_violations: u64,
    pub claude_code_execs: u64,
    pub terminal_execs: u64,
    pub package_install_execs: u64,
    pub script_execs: u64,
}

impl ExecutionTracker {
    pub fn new() -> Self {
        ExecutionTracker {
            total_executions: 0,
            scope_violations: 0,
            claude_code_execs: 0,
            terminal_execs: 0,
            package_install_execs: 0,
            script_execs: 0,
        }
    }

    pub fn record(&mut self, ctx: &ExecutionContext, is_violation: bool) {
        self.total_executions += 1;
        if is_violation {
            self.scope_violations += 1;
        }
        match ctx.source {
            ExecutionSource::ClaudeCode | ExecutionSource::Cursor | ExecutionSource::Codex => {
                self.claude_code_execs += 1;
            }
            ExecutionSource::Terminal | ExecutionSource::VscodeTerminal => {
                self.terminal_execs += 1;
            }
            ExecutionSource::NpmInstall
            | ExecutionSource::PipInstall
            | ExecutionSource::CargoInstall => {
                self.package_install_execs += 1;
            }
            ExecutionSource::Script | ExecutionSource::Unknown => {
                self.script_execs += 1;
            }
        }
    }

    pub fn summary_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_executions": self.total_executions,
            "scope_violations": self.scope_violations,
            "claude_code_execs": self.claude_code_execs,
            "terminal_execs": self.terminal_execs,
            "package_install_execs": self.package_install_execs,
            "script_execs": self.script_execs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProcessBehaviorFeatures, ProcessInfo};
    use chrono::Utc;

    fn make_process(command: &str, args: &str, parent: Option<&str>, parent_args: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: 100,
            command: command.to_string(),
            args: args.to_string(),
            process_kind: "user_app".to_string(),
            command_path_kind: "user_space".to_string(),
            parent_command: parent.map(|s| s.to_string()),
            parent_args: parent_args.map(|s| s.to_string()),
            parent_process_kind: Some("unknown".to_string()),
            parent_command_path_kind: Some("unknown".to_string()),
            behavior: ProcessBehaviorFeatures::default(),
        }
    }

    #[test]
    fn test_detect_claude_code() {
        let p = make_process("/usr/bin/git", "clone https://github.com/foo/bar", Some("/Users/user/.claude/node_modules/.bin/claude"), None);
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::ClaudeCode);
    }

    #[test]
    fn test_detect_cursor() {
        let p = make_process("/usr/bin/cargo", "build", Some("/Applications/Cursor.app/Contents/MacOS/cursor"), None);
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::Cursor);
    }

    #[test]
    fn test_detect_npm_install() {
        let p = make_process("/usr/local/bin/npm", "install axios", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::NpmInstall);
    }

    #[test]
    fn test_detect_pip_install() {
        let p = make_process("/usr/bin/pip3", "install requests", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::PipInstall);
    }

    #[test]
    fn test_detect_cargo_install() {
        let p = make_process("/Users/user/.cargo/bin/cargo", "install ripgrep", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::CargoInstall);
    }

    #[test]
    fn test_detect_terminal_interactive_shell() {
        let p = make_process("/usr/bin/git", "status", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::Terminal);
    }

    #[test]
    fn test_detect_script_noninteractive_shell() {
        let p = make_process("/usr/bin/curl", "-s https://example.com", Some("/bin/bash"), Some("-c ./deploy.sh"));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::Script);
    }

    #[test]
    fn test_detect_unknown_no_parent() {
        let p = make_process("/usr/bin/curl", "-s https://example.com", None, None);
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::Unknown);
    }

    #[test]
    fn test_npm_install_expected_behaviors() {
        let behaviors = ExecutionSource::NpmInstall.expected_behaviors();
        assert!(!behaviors.may_access_credentials);
        assert!(!behaviors.may_install_persistence);
        assert!(!behaviors.may_escalate_privileges);
        assert!(behaviors.may_access_network);
    }

    #[test]
    fn test_claude_code_expected_behaviors() {
        let behaviors = ExecutionSource::ClaudeCode.expected_behaviors();
        assert!(behaviors.may_write_files);
        assert!(behaviors.may_run_builds);
        assert!(!behaviors.may_access_credentials);
        assert!(!behaviors.may_install_persistence);
    }

    #[test]
    fn test_tracker_records_executions() {
        let mut tracker = ExecutionTracker::new();
        let p = make_process("/usr/bin/git", "pull", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        tracker.record(&ctx, false);
        assert_eq!(tracker.total_executions, 1);
        assert_eq!(tracker.scope_violations, 0);
        assert_eq!(tracker.terminal_execs, 1);
    }

    #[test]
    fn test_execution_source_as_str() {
        assert_eq!(ExecutionSource::ClaudeCode.as_str(), "claude_code");
        assert_eq!(ExecutionSource::NpmInstall.as_str(), "npm_install");
        assert_eq!(ExecutionSource::Terminal.as_str(), "terminal");
        assert_eq!(ExecutionSource::Unknown.as_str(), "unknown");
    }
}
