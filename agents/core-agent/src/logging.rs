use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;

const LOG_DIR: &str = "runtime/logs";
const LOG_FILE: &str = "runtime/logs/agent-events.jsonl";

pub fn append_event(event: &TelemetryEvent) -> Result<()> {
    ensure_log_dir()?;

    let serialized = serde_json::to_string(event).context("failed to serialize telemetry event")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .with_context(|| format!("failed to open log file at {}", LOG_FILE))?;

    writeln!(file, "{serialized}").context("failed to write telemetry event to log")?;
    Ok(())
}

fn ensure_log_dir() -> Result<()> {
    let dir = Path::new(LOG_DIR);
    if !dir.exists() {
        create_dir_all(dir).with_context(|| format!("failed to create log dir {}", LOG_DIR))?;
    }
    Ok(())
}