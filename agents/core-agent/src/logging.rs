use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const LOG_DIR_RELATIVE: &str = "runtime/logs";
const EVENT_LOG_RELATIVE: &str = "runtime/logs/agent-events.jsonl";
const RESPONSE_AUDIT_LOG_RELATIVE: &str = "runtime/logs/response-audit.jsonl";

/// Default rotation limits — overridden by agent-config.toml at runtime.
const DEFAULT_MAX_LOG_SIZE_MB: u64 = 50;
const DEFAULT_MAX_LOG_FILES: usize = 5;

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
    let (max_mb, max_files) = read_rotation_config();
    check_and_rotate(&path, max_mb, max_files);
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

// ── Log rotation ──────────────────────────────────────────────────────────────

/// Read max_log_size_mb and max_log_files from agent-config.toml.
/// Falls back to defaults if the config can't be read.
fn read_rotation_config() -> (u64, usize) {
    let config_path = resolve_project_root()
        .join("runtime")
        .join("agent-config.toml");

    let Ok(contents) = std::fs::read_to_string(&config_path) else {
        return (DEFAULT_MAX_LOG_SIZE_MB, DEFAULT_MAX_LOG_FILES);
    };

    let mut max_mb = DEFAULT_MAX_LOG_SIZE_MB;
    let mut max_files = DEFAULT_MAX_LOG_FILES;

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("max_log_size_mb") {
            let val = rest.trim().trim_start_matches('=').trim();
            if let Ok(n) = val.parse::<u64>() {
                max_mb = n;
            }
        } else if let Some(rest) = trimmed.strip_prefix("max_log_files") {
            let val = rest.trim().trim_start_matches('=').trim();
            if let Ok(n) = val.parse::<usize>() {
                max_files = n;
            }
        }
    }

    (max_mb, max_files)
}

/// Rotate `path` if it exceeds `max_size_mb` megabytes.
///
/// Rotation scheme (standard log-rotate style):
///   agent-events.jsonl.4 → deleted
///   agent-events.jsonl.3 → agent-events.jsonl.4
///   ...
///   agent-events.jsonl.1 → agent-events.jsonl.2
///   agent-events.jsonl   → agent-events.jsonl.1
///   agent-events.jsonl   → (new empty file)
///
/// Non-fatal: any I/O errors during rotation are printed to stderr but do not
/// propagate — the append that follows will create a new file if needed.
fn check_and_rotate(path: &PathBuf, max_size_mb: u64, max_files: usize) {
    let size_bytes = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return, // file doesn't exist yet — nothing to rotate
    };

    let limit_bytes = max_size_mb * 1024 * 1024;
    if size_bytes <= limit_bytes {
        return; // within limit
    }

    eprintln!(
        "[core-agent] rotating {} ({} MB > {} MB limit)",
        path.display(),
        size_bytes / (1024 * 1024),
        max_size_mb
    );

    // Delete the oldest rotated file if we're at the limit
    if max_files > 0 {
        let oldest = rotated_path(path, max_files);
        if oldest.exists() {
            let _ = std::fs::remove_file(&oldest);
        }
    }

    // Shift existing rotated files: .N-1 → .N, ..., .1 → .2
    for i in (1..max_files).rev() {
        let src = rotated_path(path, i);
        let dst = rotated_path(path, i + 1);
        if src.exists() {
            let _ = std::fs::rename(&src, &dst);
        }
    }

    // Rename the active log to .1
    let dst1 = rotated_path(path, 1);
    if let Err(e) = std::fs::rename(path, &dst1) {
        eprintln!("[core-agent] rotation rename failed: {e}");
        return;
    }

    eprintln!(
        "[core-agent] rotation complete: {} → {}",
        path.display(),
        dst1.display()
    );
}

fn rotated_path(base: &PathBuf, n: usize) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}
