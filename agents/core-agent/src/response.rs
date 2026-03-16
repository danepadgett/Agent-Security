use crate::config::ResponsePolicy;
use crate::guardrails::{
    path_kind, should_allow_file_quarantine, should_allow_process_kill, FileQuarantineRequest,
    ProcessKillRequest,
};
use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const QUARANTINE_DIR: &str = "runtime/quarantine";

pub fn handle_detection(event: &TelemetryEvent, policy: &ResponsePolicy) -> Result<Vec<TelemetryEvent>> {
    let mut out = Vec::new();
    let score = alert_score(event);

    let kill_targets = collect_process_kill_targets(event);
    let quarantine_targets = collect_file_quarantine_targets(event);

    if policy.enable_process_kill && score >= policy.kill_threshold {
        for target in kill_targets {
            let request = ProcessKillRequest {
                pid: target.pid,
                process_kind: target.process_kind.as_deref(),
                path: target.associated_path.as_deref(),
                score,
                original_event_type: event.event_type.as_str(),
                chain_root_pid: target.chain_root_pid,
                is_root_process: target.is_root_process,
            };

            match should_allow_process_kill(&request, policy) {
                Ok(()) => {
                    if policy.simulation_mode {
                        out.push(build_response_event(
                            "response_simulated_process_kill",
                            json!({
                                "original_event_type": event.event_type,
                                "pid": target.pid,
                                "score": score,
                                "process_kind": target.process_kind,
                                "associated_path": target.associated_path,
                                "chain_root_pid": target.chain_root_pid,
                                "is_root_process": target.is_root_process,
                                "reason": "Policy threshold met for process kill, but simulation mode is enabled"
                            }),
                        ));
                    } else if kill_process(target.pid)? {
                        out.push(build_response_event(
                            "response_process_killed",
                            json!({
                                "original_event_type": event.event_type,
                                "pid": target.pid,
                                "score": score,
                                "process_kind": target.process_kind,
                                "associated_path": target.associated_path,
                                "chain_root_pid": target.chain_root_pid,
                                "is_root_process": target.is_root_process
                            }),
                        ));
                    }
                }
                Err(reason) => {
                    out.push(build_response_event(
                        "response_blocked_by_guardrail",
                        json!({
                            "action": "process_kill",
                            "original_event_type": event.event_type,
                            "score": score,
                            "pid": target.pid,
                            "process_kind": target.process_kind,
                            "associated_path": target.associated_path,
                            "chain_root_pid": target.chain_root_pid,
                            "is_root_process": target.is_root_process,
                            "reason": reason
                        }),
                    ));
                }
            }
        }
    }

    if policy.enable_file_quarantine && score >= policy.quarantine_threshold {
        for path in quarantine_targets {
            let classified_path_kind = path_kind(&path);

            let request = FileQuarantineRequest {
                path: &path,
                score,
                original_event_type: event.event_type.as_str(),
                path_kind: &classified_path_kind,
            };

            match should_allow_file_quarantine(&request, policy) {
                Ok(()) => {
                    if policy.simulation_mode {
                        out.push(build_response_event(
                            "response_simulated_file_quarantine",
                            json!({
                                "original_event_type": event.event_type,
                                "path": path,
                                "path_kind": classified_path_kind,
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
                                "path_kind": classified_path_kind,
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
                            "path_kind": classified_path_kind,
                            "reason": reason
                        }),
                    ));
                }
            }
        }
    }

    Ok(out)
}

#[derive(Debug, Clone)]
struct ProcessKillTarget {
    pid: i32,
    process_kind: Option<String>,
    associated_path: Option<String>,
    chain_root_pid: Option<i32>,
    is_root_process: bool,
}

fn build_response_event(event_type: &str, payload: Value) -> TelemetryEvent {
    TelemetryEvent::new(Utc::now(), event_type, "core-agent/response", payload)
}

fn alert_score(event: &TelemetryEvent) -> u8 {
    event.payload
        .get("score")
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0)
}

fn collect_process_kill_targets(event: &TelemetryEvent) -> Vec<ProcessKillTarget> {
    let details = match event.payload.get("details") {
        Some(details) => details,
        None => return Vec::new(),
    };

    let chain_root_pid = details
        .get("chain_root_pid")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok());

    let related_paths = extract_string_array(details.get("related_paths"));

    let associated_path = details
        .get("primary_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            details
                .get("matched_download_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| related_paths.first().cloned());

    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(pids) = details.get("involved_pids").and_then(|v| v.as_array()) {
        for pid_value in pids {
            let Some(pid_i64) = pid_value.as_i64() else {
                continue;
            };
            let Ok(pid) = i32::try_from(pid_i64) else {
                continue;
            };

            if !seen.insert(pid) {
                continue;
            }

            targets.push(ProcessKillTarget {
                pid,
                process_kind: details
                    .get("chosen_process_kind")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        details
                            .get("child_process_kind")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .or_else(|| {
                        details
                            .get("process_kind")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    }),
                associated_path: associated_path.clone(),
                chain_root_pid,
                is_root_process: chain_root_pid.map(|root| root == pid).unwrap_or(false),
            });
        }
    }

    if targets.is_empty() {
        if let Some(pid) = extract_single_pid(details) {
            targets.push(ProcessKillTarget {
                pid,
                process_kind: details
                    .get("chosen_process_kind")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        details
                            .get("child_process_kind")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .or_else(|| {
                        details
                            .get("process_kind")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    }),
                associated_path,
                chain_root_pid,
                is_root_process: chain_root_pid.map(|root| root == pid).unwrap_or(false),
            });
        }
    }

    targets
}

fn collect_file_quarantine_targets(event: &TelemetryEvent) -> Vec<String> {
    let details = match event.payload.get("details") {
        Some(details) => details,
        None => return Vec::new(),
    };

    let mut targets = BTreeSet::new();

    if let Some(path) = details.get("primary_path").and_then(|v| v.as_str()) {
        targets.insert(path.to_string());
    }

    if let Some(path) = details.get("matched_download_path").and_then(|v| v.as_str()) {
        targets.insert(path.to_string());
    }

    if let Some(path) = details.get("path").and_then(|v| v.as_str()) {
        targets.insert(path.to_string());
    }

    for path in extract_string_array(details.get("related_paths")) {
        targets.insert(path);
    }

    targets.into_iter().collect()
}

fn extract_single_pid(details: &Value) -> Option<i32> {
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
        .or_else(|| {
            details
                .get("parent_pid")
                .and_then(|v| v.as_i64())
                .and_then(|v| i32::try_from(v).ok())
        })
}

fn extract_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| {
            items.iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
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