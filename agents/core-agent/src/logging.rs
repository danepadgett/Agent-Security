use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;

const LOG_DIR: &str = "runtime/logs";
const EVENT_LOG_FILE: &str = "runtime/logs/agent-events.jsonl";
const RESPONSE_AUDIT_LOG_FILE: &str = "runtime/logs/response-audit.jsonl";

pub fn append_event(event: &TelemetryEvent) -> Result<()> {
    append_jsonl(EVENT_LOG_FILE, event)
}

pub fn append_response_audit(event: &TelemetryEvent) -> Result<()> {
    if !event.event_type.starts_with("response_") {
        return Ok(());
    }

    append_jsonl(RESPONSE_AUDIT_LOG_FILE, event)
}

fn append_jsonl(path: &str, event: &TelemetryEvent) -> Result<()> {
    ensure_log_dir()?;

    let serialized =
        serde_json::to_string(event).context("failed to serialize telemetry event")?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log file at {}", path))?;

    writeln!(file, "{serialized}")
        .with_context(|| format!("failed to write telemetry event to {}", path))?;

    Ok(())
}

fn ensure_log_dir() -> Result<()> {
    let dir = Path::new(LOG_DIR);

    if !dir.exists() {
        create_dir_all(dir).with_context(|| format!("failed to create log dir {}", LOG_DIR))?;
    }

    Ok(())
}