use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const LOG_DIR_RELATIVE: &str = "runtime/logs";
const EVENT_LOG_RELATIVE: &str = "runtime/logs/agent-events.jsonl";
const RESPONSE_AUDIT_LOG_RELATIVE: &str = "runtime/logs/response-audit.jsonl";

/// Resolve the project root directory.
///
/// Resolution order:
///   1. `AGENT_SECURITY_ROOT` env var — explicit override.
///   2. Navigate up from the current executable path.
///      Binary is expected at `<root>/agents/core-agent/target/debug/core-agent`
///      or `<root>/agents/core-agent/target/release/core-agent`, so we go up
///      4 parents: binary → debug/release → target → core-agent → agents → root.
///   3. Fall back to the current working directory.
pub fn resolve_project_root() -> PathBuf {
    // 1. Explicit env var override
    if let Ok(root) = std::env::var("AGENT_SECURITY_ROOT") {
        let path = PathBuf::from(&root);
        if path.is_dir() {
            return path;
        }
        eprintln!(
            "[core-agent] WARNING: AGENT_SECURITY_ROOT={root} is not a directory, ignoring"
        );
    }

    // 2. Navigate up from executable path
    //    <root>/agents/core-agent/target/debug/core-agent
    //    parent = debug/release, parent = target, parent = core-agent, parent = agents, parent = root
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe
            .parent() // debug or release
            .and_then(|p| p.parent()) // target
            .and_then(|p| p.parent()) // core-agent
            .and_then(|p| p.parent()) // agents
            .and_then(|p| p.parent()) // project root
            .map(|p| p.to_path_buf());

        if let Some(root) = candidate {
            if root.is_dir() {
                return root;
            }
        }
    }

    // 3. Fall back to current working directory
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn project_root_path() -> PathBuf {
    resolve_project_root()
}

pub fn log_file_path() -> PathBuf {
    resolve_project_root().join(EVENT_LOG_RELATIVE)
}

pub fn response_audit_log_path() -> PathBuf {
    resolve_project_root().join(RESPONSE_AUDIT_LOG_RELATIVE)
}

pub fn append_event(event: &TelemetryEvent) -> Result<()> {
    let path = log_file_path();
    append_jsonl_path(&path, event)
}

pub fn append_response_audit(event: &TelemetryEvent) -> Result<()> {
    if !event.event_type.starts_with("response_") {
        return Ok(());
    }

    let path = response_audit_log_path();
    append_jsonl_path(&path, event)
}

fn append_jsonl_path(path: &PathBuf, event: &TelemetryEvent) -> Result<()> {
    ensure_log_dir()?;

    let serialized =
        serde_json::to_string(event).context("failed to serialize telemetry event")?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log file at {}", path.display()))?;

    writeln!(file, "{serialized}")
        .with_context(|| format!("failed to write telemetry event to {}", path.display()))?;

    Ok(())
}

fn ensure_log_dir() -> Result<()> {
    let dir = resolve_project_root().join(LOG_DIR_RELATIVE);

    if !dir.exists() {
        create_dir_all(&dir)
            .with_context(|| format!("failed to create log dir {}", dir.display()))?;
    }

    Ok(())
}
