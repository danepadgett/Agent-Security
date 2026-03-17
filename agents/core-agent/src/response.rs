use crate::config::ResponsePolicy;
use crate::guardrails::{
    path_kind, should_allow_file_quarantine, should_allow_process_kill, FileQuarantineRequest,
    ProcessKillRequest,
};
use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const QUARANTINE_DIR: &str = "runtime/quarantine";

pub fn handle_detection(event: &TelemetryEvent, policy: &ResponsePolicy) -> Result<Vec<TelemetryEvent>> {
    let mut out = Vec::new();
    let score = alert_score(event);
    let attack_chain_length = extract_attack_chain_length(event);
    let confidence = extract_confidence(event);

    let kill_targets = scoped_process_kill_targets(event);
    let quarantine_targets = scoped_file_quarantine_targets(event);

    if policy.enable_process_kill && score >= policy.kill_threshold {
        for target in kill_targets {
            let request = ProcessKillRequest {
                pid: target.pid,
                process_kind: target.process_kind.as_deref(),
                associated_path: target.associated_path.as_deref(),
                score,
                original_event_type: event.event_type.as_str(),
                chain_root_pid: target.chain_root_pid,
                is_root_process: target.is_root_process,
                attack_chain_length,
                confidence: confidence.as_deref(),
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
                                "confidence": confidence,
                                "process_kind": target.process_kind,
                                "associated_path": target.associated_path,
                                "chain_root_pid": target.chain_root_pid,
                                "is_root_process": target.is_root_process,
                                "selection_reason": target.selection_reason,
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
                                "confidence": confidence,
                                "process_kind": target.process_kind,
                                "associated_path": target.associated_path,
                                "chain_root_pid": target.chain_root_pid,
                                "is_root_process": target.is_root_process,
                                "selection_reason": target.selection_reason
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
                            "confidence": confidence,
                            "pid": target.pid,
                            "process_kind": target.process_kind,
                            "associated_path": target.associated_path,
                            "chain_root_pid": target.chain_root_pid,
                            "is_root_process": target.is_root_process,
                            "selection_reason": target.selection_reason,
                            "reason": reason
                        }),
                    ));
                }
            }
        }
    }

    if policy.enable_file_quarantine && score >= policy.quarantine_threshold {
        for target in quarantine_targets {
            let classified_path_kind = path_kind(&target.path);

            let request = FileQuarantineRequest {
                path: &target.path,
                score,
                original_event_type: event.event_type.as_str(),
                path_kind: &classified_path_kind,
                confidence: confidence.as_deref(),
                attack_chain_length,
            };

            match should_allow_file_quarantine(&request, policy) {
                Ok(()) => {
                    if policy.simulation_mode {
                        out.push(build_response_event(
                            "response_simulated_file_quarantine",
                            json!({
                                "original_event_type": event.event_type,
                                "path": target.path,
                                "path_kind": classified_path_kind,
                                "score": score,
                                "confidence": confidence,
                                "selection_reason": target.selection_reason,
                                "reason": "Policy threshold met for file quarantine, but simulation mode is enabled"
                            }),
                        ));
                    } else if let Some(new_path) = quarantine_file(&target.path)? {
                        out.push(build_response_event(
                            "response_file_quarantined",
                            json!({
                                "original_event_type": event.event_type,
                                "old_path": target.path,
                                "new_path": new_path,
                                "path_kind": classified_path_kind,
                                "score": score,
                                "confidence": confidence,
                                "selection_reason": target.selection_reason
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
                            "confidence": confidence,
                            "path": target.path,
                            "path_kind": classified_path_kind,
                            "selection_reason": target.selection_reason,
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
    selection_reason: String,
}

#[derive(Debug, Clone)]
struct FileQuarantineTarget {
    path: String,
    selection_reason: String,
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

fn extract_attack_chain_length(event: &TelemetryEvent) -> usize {
    event.payload
        .get("details")
        .and_then(|d| d.get("attack_chain_length"))
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(1)
}

fn extract_confidence(event: &TelemetryEvent) -> Option<String> {
    event.payload
        .get("details")
        .and_then(|d| d.get("confidence"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn scoped_process_kill_targets(event: &TelemetryEvent) -> Vec<ProcessKillTarget> {
    let Some(details) = event.payload.get("details") else {
        return Vec::new();
    };

    let chain_root_pid = details
        .get("chain_root_pid")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok());

    let chosen_process_kind = details
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
        });

    let associated_path = preferred_associated_path(details);

    let timeline = details
        .get("timeline")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let involved_pids = details
        .get("involved_pids")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut pid_activity: BTreeMap<i32, usize> = BTreeMap::new();
    let mut parent_seen: BTreeSet<i32> = BTreeSet::new();
    let mut child_seen: BTreeSet<i32> = BTreeSet::new();

    for step in &timeline {
        if let Some(pid) = step
            .get("pid")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
        {
            *pid_activity.entry(pid).or_insert(0) += 1;
            child_seen.insert(pid);
        }

        if let Some(parent_pid) = step
            .get("parent_pid")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
        {
            parent_seen.insert(parent_pid);
        }
    }

    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();

    for pid_value in involved_pids {
        let Some(pid_i64) = pid_value.as_i64() else {
            continue;
        };
        let Ok(pid) = i32::try_from(pid_i64) else {
            continue;
        };

        if !seen.insert(pid) {
            continue;
        }

        let is_root_process = chain_root_pid.map(|root| root == pid).unwrap_or(false);
        let is_leaf = !parent_seen.contains(&pid) && child_seen.contains(&pid);
        let activity_count = pid_activity.get(&pid).copied().unwrap_or(0);

        let selection_reason = if is_leaf && !is_root_process {
            "selected as descendant/leaf process in the incident chain".to_string()
        } else if activity_count > 1 && !is_root_process {
            "selected due to repeated activity within the incident timeline".to_string()
        } else if is_root_process {
            "selected as chain root process".to_string()
        } else {
            "selected as involved process in the incident chain".to_string()
        };

        targets.push(ProcessKillTarget {
            pid,
            process_kind: chosen_process_kind.clone(),
            associated_path: associated_path.clone(),
            chain_root_pid,
            is_root_process,
            selection_reason,
        });
    }

    targets.sort_by_key(|target| {
        let is_leaf = if let Some(root) = chain_root_pid {
            target.pid != root && !parent_seen.contains(&target.pid)
        } else {
            !parent_seen.contains(&target.pid)
        };

        let priority_bucket = if is_leaf && !target.is_root_process {
            0
        } else if !target.is_root_process {
            1
        } else {
            2
        };

        (priority_bucket, target.pid)
    });

    targets
}

fn scoped_file_quarantine_targets(event: &TelemetryEvent) -> Vec<FileQuarantineTarget> {
    let Some(details) = event.payload.get("details") else {
        return Vec::new();
    };

    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(path) = details.get("primary_path").and_then(|v| v.as_str()) {
        if seen.insert(path.to_string()) {
            targets.push(FileQuarantineTarget {
                path: path.to_string(),
                selection_reason: "selected as primary incident artifact".to_string(),
            });
        }
    }

    if let Some(path) = details.get("matched_download_path").and_then(|v| v.as_str()) {
        if seen.insert(path.to_string()) {
            targets.push(FileQuarantineTarget {
                path: path.to_string(),
                selection_reason: "selected as matched download artifact".to_string(),
            });
        }
    }

    if let Some(path) = details.get("path").and_then(|v| v.as_str()) {
        if seen.insert(path.to_string()) {
            targets.push(FileQuarantineTarget {
                path: path.to_string(),
                selection_reason: "selected as direct detection artifact".to_string(),
            });
        }
    }

    if let Some(path) = details.get("persistence_path").and_then(|v| v.as_str()) {
        if seen.insert(path.to_string()) {
            targets.push(FileQuarantineTarget {
                path: path.to_string(),
                selection_reason: "selected as persistence-related artifact".to_string(),
            });
        }
    }

    if let Some(paths) = details.get("related_paths").and_then(|v| v.as_array()) {
        for path in paths.iter().filter_map(|v| v.as_str()) {
            if seen.insert(path.to_string()) {
                targets.push(FileQuarantineTarget {
                    path: path.to_string(),
                    selection_reason: "selected as related artifact from incident chain".to_string(),
                });
            }
        }
    }

    targets.sort_by_key(|target| quarantine_priority(&target.path));
    targets
}

fn preferred_associated_path(details: &Value) -> Option<String> {
    details
        .get("primary_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            details
                .get("matched_download_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            details
                .get("persistence_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            details
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn quarantine_priority(path: &str) -> (u8, String) {
    let lower = path.to_ascii_lowercase();

    let bucket = if lower.contains("/downloads/") {
        0
    } else if lower.contains("/library/launchagents/")
        || lower.contains("/library/launchdaemons/")
        || lower.ends_with(".plist")
    {
        1
    } else {
        2
    };

    (bucket, lower)
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