// Classifies where a process originated — developer terminal, IDE, CI pipeline, or script.
// Used by the scope violation detector to provide execution context in alerts.

use chrono::{DateTime, Utc};
use crate::models::ProcessInfo;

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionSource {
    Terminal, // Direct terminal invocation (zsh, bash, iTerm, Terminal.app)
    IDE,      // From an IDE (VS Code, Cursor, Xcode, JetBrains)
    CI,       // CI/CD pipeline (GitHub Actions, CircleCI, Jenkins)
    Script,   // Non-interactive script execution
    Unknown,
}

impl ExecutionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionSource::Terminal => "terminal",
            ExecutionSource::IDE => "ide",
            ExecutionSource::CI => "ci",
            ExecutionSource::Script => "script",
            ExecutionSource::Unknown => "unknown",
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
        let source = classify_source(process);
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

fn classify_source(process: &ProcessInfo) -> ExecutionSource {
    // CI/CD environment detection via well-known env vars
    if std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("CIRCLECI").is_ok()
        || std::env::var("JENKINS_HOME").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("BUILDKITE").is_ok()
    {
        return ExecutionSource::CI;
    }

    let parent = process.parent_command.as_deref().unwrap_or("").to_lowercase();
    let parent_basename = parent.rsplit('/').next().unwrap_or(&parent);

    // IDE parent process detection
    let ide_parents = [
        "code",      // VS Code
        "cursor",    // Cursor
        "xcode",     // Xcode
        "idea",      // IntelliJ IDEA
        "goland",    // GoLand
        "pycharm",   // PyCharm
        "webstorm",  // WebStorm
        "rubymine",  // RubyMine
        "clion",     // CLion
        "phpstorm",  // PHPStorm
        "rider",     // Rider
        "datagrip",  // DataGrip
        "nova",      // Nova
        "fleet",     // JetBrains Fleet
        "zed",       // Zed editor
    ];
    if ide_parents.iter().any(|&ide| parent_basename.contains(ide)) {
        return ExecutionSource::IDE;
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
        // -i flag or no args means interactive shell
        if parent_args.contains("-i") || parent_args.is_empty() {
            return ExecutionSource::Terminal;
        }
        // -c flag with a script path means non-interactive script execution
        return ExecutionSource::Script;
    }

    // Script execution via interpreter
    let interpreters = ["python", "python3", "ruby", "perl", "node", "deno", "bun"];
    if interpreters.iter().any(|&interp| parent_basename.starts_with(interp)) {
        return ExecutionSource::Script;
    }

    ExecutionSource::Unknown
}

/// Tracks executions seen in the current agent session. Used to provide
/// session-level summary stats to the UI (total execs, scope violations, sources).
pub struct ExecutionTracker {
    pub total_executions: u64,
    pub scope_violations: u64,
    pub terminal_execs: u64,
    pub ide_execs: u64,
    pub ci_execs: u64,
    pub script_execs: u64,
}

impl ExecutionTracker {
    pub fn new() -> Self {
        ExecutionTracker {
            total_executions: 0,
            scope_violations: 0,
            terminal_execs: 0,
            ide_execs: 0,
            ci_execs: 0,
            script_execs: 0,
        }
    }

    pub fn record(&mut self, ctx: &ExecutionContext, is_violation: bool) {
        self.total_executions += 1;
        if is_violation {
            self.scope_violations += 1;
        }
        match ctx.source {
            ExecutionSource::Terminal => self.terminal_execs += 1,
            ExecutionSource::IDE => self.ide_execs += 1,
            ExecutionSource::CI => self.ci_execs += 1,
            ExecutionSource::Script => self.script_execs += 1,
            ExecutionSource::Unknown => {}
        }
    }

    pub fn summary_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_executions": self.total_executions,
            "scope_violations": self.scope_violations,
            "terminal_execs": self.terminal_execs,
            "ide_execs": self.ide_execs,
            "ci_execs": self.ci_execs,
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
    fn test_classify_ide_vscode() {
        let p = make_process("/usr/bin/npm", "install", Some("/usr/share/code/code"), None);
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::IDE);
    }

    #[test]
    fn test_classify_ide_cursor() {
        let p = make_process("/usr/bin/cargo", "build", Some("/Applications/Cursor.app/Contents/MacOS/cursor"), None);
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::IDE);
    }

    #[test]
    fn test_classify_terminal_interactive_shell() {
        let p = make_process("/usr/bin/git", "status", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::Terminal);
    }

    #[test]
    fn test_classify_script_noninteractive_shell() {
        let p = make_process("/usr/bin/curl", "-s https://example.com", Some("/bin/bash"), Some("-c ./deploy.sh"));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::Script);
    }

    #[test]
    fn test_classify_unknown_no_parent() {
        let p = make_process("/usr/bin/curl", "-s https://example.com", None, None);
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        assert_eq!(ctx.source, ExecutionSource::Unknown);
    }

    #[test]
    fn test_tracker_records_clean_exec() {
        let mut tracker = ExecutionTracker::new();
        let p = make_process("/usr/bin/git", "pull", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        tracker.record(&ctx, false);
        assert_eq!(tracker.total_executions, 1);
        assert_eq!(tracker.scope_violations, 0);
        assert_eq!(tracker.terminal_execs, 1);
    }

    #[test]
    fn test_tracker_records_violation() {
        let mut tracker = ExecutionTracker::new();
        let p = make_process("/usr/bin/curl", "| bash", Some("/bin/zsh"), Some(""));
        let ctx = ExecutionContext::from_process(&p, Utc::now());
        tracker.record(&ctx, true);
        assert_eq!(tracker.scope_violations, 1);
        assert_eq!(tracker.total_executions, 1);
    }

    #[test]
    fn test_execution_source_as_str() {
        assert_eq!(ExecutionSource::Terminal.as_str(), "terminal");
        assert_eq!(ExecutionSource::IDE.as_str(), "ide");
        assert_eq!(ExecutionSource::CI.as_str(), "ci");
        assert_eq!(ExecutionSource::Script.as_str(), "script");
        assert_eq!(ExecutionSource::Unknown.as_str(), "unknown");
    }
}
