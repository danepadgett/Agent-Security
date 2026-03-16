use crate::config::ResponsePolicy;
use crate::guardrails::{should_allow_file_quarantine, should_allow_process_kill};
use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const QUARANTINE_DIR: &str = "runtime/quarantine";

pub fn handle_detection(event: &TelemetryEvent, policy: &ResponsePolicy) -> Result<Vec<TelemetryEvent>> {
    let mut out = Vec::new();
    let score = alert_score(event);

    if policy.enable_process_kill && score >= policy.kill_threshold {
        let pid = extract_pid(event);
        let process_kind = extract_chosen_process_kind(event);
        let path = extract_file_path(event);

        match should_allow_process_kill(process_kind.as_deref(), path.as_deref(), policy) {
            Ok(()) => {
                if let Some(pid) = pid {
                    if policy.simulation_mode {
                        out.push(build_response_event(
                            "response_simulated_process_kill",
                            json!({
                                "original_event_type": event.event_type,
                                "pid": pid,
                                "score": score,
                                "process_kind": process_kind,
                                "path": path,
                                "reason": "Policy threshold met for process kill, but simulation mode is enabled"
                            }),
                        ));
                    } else if kill_process(pid)? {
                        out.push(build_response_event(
                            "response_process_killed",
                            json!({
                                "original_event_type": event.event_type,
                                "pid": pid,
                                "score": score,
                                "process_kind": process_kind,
                                "path": path
                            }),
                        ));
                    }
                }
            }
            Err(reason) => {
                out.push(build_response_event(
                    "response_blocked_by_guardrail",
                    json!({
                        "action": "process_kill",
                        "original_event_type": event.event_type,
                        "score": score,
                        "pid": pid,
                        "process_kind": process_kind,
                        "path": path,
                        "reason": reason
                    }),
                ));
            }
        }
    }

    if policy.enable_file_quarantine && score >= policy.quarantine_threshold {
        if let Some(path) = extract_file_path(event) {
            match should_allow_file_quarantine(&path, policy) {
                Ok(()) => {
                    if policy.simulation_mode {
                        out.push(build_response_event(
                            "response_simulated_file_quarantine",
                            json!({
                                "original_event_type": event.event_type,
                                "path": path,
                                "score": score,
                                "reason": "Policy threshold met for file quarantine, but simulation mode is enabled"
                            }),
                        ));
                    } else if let Some(new_path) = quarantine_file(&path)? {
                        out.push(build_response_event(
                            "response_file_quarantined",
                            json!({
                                "original_event_type": event.event_type,
                                "old_path": path,
                                "new_path": new_path,
                                "score": score
                            }),
                        ));
                    }
                }
                Err(reason) => {
                    out.push(build_response_event(
                        "response_blocked_by_guardrail",
                        json!({
                            "action": "file_quarantine",
                            "original_event_type": event.event_type,
                            "score": score,
                            "path": path,
                            "reason": reason
                        }),
                    ));
                }
            }
        }
    }

    Ok(out)
}

fn build_response_event(event_type: &str, payload: serde_json::Value) -> TelemetryEvent {
    TelemetryEvent::new(Utc::now(), event_type, "core-agent/response", payload)
}

fn alert_score(event: &TelemetryEvent) -> u8 {
    event.payload
        .get("score")
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0)
}

fn extract_pid(event: &TelemetryEvent) -> Option<i32> {
    let details = event.payload.get("details")?;

    details
        .get("pid")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
        .or_else(|| {
            details
                .get("child_pid")
                .and_then(|v| v.as_i64())
                .and_then(|v| i32::try_from(v).ok())
        })
}

fn extract_file_path(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("matched_download_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            details
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn extract_chosen_process_kind(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("chosen_process_kind")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            details
                .get("process_kind")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            details
                .get("child_process_kind")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn kill_process(pid: i32) -> Result<bool> {
    let status = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .with_context(|| format!("failed to execute kill for pid {}", pid))?;

    Ok(status.success())
}

fn quarantine_file(original_path: &str) -> Result<Option<String>> {
    let source = Path::new(original_path);
    if !source.exists() {
        return Ok(None);
    }

    fs::create_dir_all(QUARANTINE_DIR)
        .with_context(|| format!("failed to create {}", QUARANTINE_DIR))?;

    let file_name = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("quarantined_item");

    let timestamp = Utc::now().timestamp();
    let dest_name = format!("{}_{}", timestamp, file_name);
    let dest_path: PathBuf = Path::new(QUARANTINE_DIR).join(dest_name);

    fs::rename(source, &dest_path).with_context(|| {
        format!(
            "failed to move {} to {}",
            source.display(),
            dest_path.display()
        )
    })?;

    Ok(Some(dest_path.to_string_lossy().to_string()))
}