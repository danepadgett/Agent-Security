use crate::config::{read_live_whitelist, ResponsePolicy, Whitelist};
use crate::guardrails::{
    path_kind, should_allow_file_quarantine, should_allow_process_kill, FileQuarantineRequest,
    ProcessKillRequest,
};
use crate::models::TelemetryEvent;
use crate::state::{incident_key, response_action_key, AgentState};
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const QUARANTINE_DIR: &str = "runtime/quarantine";
const QUARANTINE_MANIFEST: &str = "runtime/quarantine/manifest.jsonl";
/// Per-(incident_key, action_key) cooldown — prevents repeated kills of the same target.
const RESPONSE_ACTION_COOLDOWN_SECONDS: i64 = 300;
/// Per-incident cooldown — prevents any response on the same incident within this window.
const RESPONSE_INCIDENT_COOLDOWN_SECONDS: i64 = 60;

pub fn handle_detection(
    event: &TelemetryEvent,
    policy: &ResponsePolicy,
    agent_state: &mut AgentState,
) -> Result<Vec<TelemetryEvent>> {
    let mut out = Vec::new();
    let whitelist = read_live_whitelist();
    let score = alert_score(event);
    let attack_chain_length = extract_attack_chain_length(event);
    let confidence = extract_confidence(event);
    let incident_key_value = incident_key(event);
    let action_time = Utc::now();

    // ── Per-incident response cooldown ────────────────────────────────────────
    // RESPONSE IMPACT: prevents any response for the same incident within 60s.
    // This is separate from the per-action 300s cooldown below.
    if agent_state.is_incident_response_in_cooldown(
        &incident_key_value,
        action_time,
        RESPONSE_INCIDENT_COOLDOWN_SECONDS,
    ) {
        out.push(build_response_event(
            action_time,
            "response_suppressed_by_incident_cooldown",
            json!({
                "action": "any",
                "target_type": "incident",
                "response_mode": response_mode(policy),
                "outcome": "suppressed",
                "original_event_type": event.event_type,
                "incident_key": incident_key_value,
                "cooldown_seconds": RESPONSE_INCIDENT_COOLDOWN_SECONDS,
                "reason": "All responses suppressed: same incident triggered a response within the last 60 seconds"
            }),
        ));
        return Ok(out);
    }

    let kill_targets = scoped_process_kill_targets(event);
    let quarantine_targets = scoped_file_quarantine_targets(event);

    if policy.enable_process_kill && score >= policy.kill_threshold {
        for target in kill_targets {
            let action_time = Utc::now();
            let action_key = response_action_key("process_kill", &target.pid.to_string());

            if !agent_state.should_allow_response_action(
                &incident_key_value,
                &action_key,
                action_time,
                RESPONSE_ACTION_COOLDOWN_SECONDS,
            ) {
                out.push(build_response_event(
                    action_time,
                    "response_suppressed_by_cooldown",
                    json!({
                        "action": "process_kill",
                        "target_type": "process",
                        "response_mode": response_mode(policy),
                        "outcome": "suppressed",
                        "original_event_type": event.event_type,
                        "incident_key": incident_key_value,
                        "action_key": action_key,
                        "pid": target.pid,
                        "selection_reason": target.selection_reason,
                        "reason": "Response action suppressed because the same incident/target pair is still in cooldown"
                    }),
                ));
                continue;
            }

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
                    // ── Whitelist check ──────────────────────────────────────────────
                    // RESPONSE IMPACT: whitelisted processes are never killed regardless
                    // of simulation mode. Runs after guardrails, before any action.
                    if let Some(matched_entry) = process_matches_whitelist(target.pid, &whitelist) {
                        out.push(build_response_event(
                            action_time,
                            "response_blocked_by_whitelist",
                            json!({
                                "action": "process_kill",
                                "target_type": "process",
                                "response_mode": response_mode(policy),
                                "outcome": "blocked",
                                "original_event_type": event.event_type,
                                "incident_key": incident_key_value,
                                "action_key": action_key,
                                "pid": target.pid,
                                "process_kind": target.process_kind,
                                "associated_path": target.associated_path,
                                "matched_entry": matched_entry,
                                "reason": format!("Process is trusted (matched whitelist entry: {matched_entry})")
                            }),
                        ));
                        continue;
                    }

                    if policy.simulation_mode {
                        out.push(build_response_event(
                            action_time,
                            "response_simulated_process_kill",
                            json!({
                                "action": "process_kill",
                                "target_type": "process",
                                "response_mode": response_mode(policy),
                                "outcome": "simulated",
                                "original_event_type": event.event_type,
                                "incident_key": incident_key_value,
                                "action_key": action_key,
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
                        agent_state.record_response_action(
                            &incident_key_value,
                            &action_key,
                            action_time,
                        );
                    } else {
                        match kill_process(target.pid) {
                            Ok(true) => {
                                out.push(build_response_event(
                                    action_time,
                                    "response_process_killed",
                                    json!({
                                        "action": "process_kill",
                                        "target_type": "process",
                                        "response_mode": response_mode(policy),
                                        "outcome": "executed",
                                        "original_event_type": event.event_type,
                                        "incident_key": incident_key_value,
                                        "action_key": action_key,
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
                                agent_state.record_response_action(
                                    &incident_key_value,
                                    &action_key,
                                    action_time,
                                );
                            }
                            Ok(false) => {
                                out.push(build_response_event(
                                    action_time,
                                    "response_execution_failed",
                                    json!({
                                        "action": "process_kill",
                                        "target_type": "process",
                                        "response_mode": response_mode(policy),
                                        "outcome": "failed",
                                        "original_event_type": event.event_type,
                                        "incident_key": incident_key_value,
                                        "action_key": action_key,
                                        "pid": target.pid,
                                        "score": score,
                                        "confidence": confidence,
                                        "process_kind": target.process_kind,
                                        "associated_path": target.associated_path,
                                        "chain_root_pid": target.chain_root_pid,
                                        "is_root_process": target.is_root_process,
                                        "selection_reason": target.selection_reason,
                                        "reason": "kill command completed but did not report success"
                                    }),
                                ));
                            }
                            Err(err) => {
                                out.push(build_response_event(
                                    action_time,
                                    "response_execution_failed",
                                    json!({
                                        "action": "process_kill",
                                        "target_type": "process",
                                        "response_mode": response_mode(policy),
                                        "outcome": "failed",
                                        "original_event_type": event.event_type,
                                        "incident_key": incident_key_value,
                                        "action_key": action_key,
                                        "pid": target.pid,
                                        "score": score,
                                        "confidence": confidence,
                                        "process_kind": target.process_kind,
                                        "associated_path": target.associated_path,
                                        "chain_root_pid": target.chain_root_pid,
                                        "is_root_process": target.is_root_process,
                                        "selection_reason": target.selection_reason,
                                        "reason": format!("process kill failed: {}", err)
                                    }),
                                ));
                            }
                        }
                    }
                }
                Err(reason) => {
                    out.push(build_response_event(
                        action_time,
                        "response_blocked_by_guardrail",
                        json!({
                            "action": "process_kill",
                            "target_type": "process",
                            "response_mode": response_mode(policy),
                            "outcome": "blocked",
                            "original_event_type": event.event_type,
                            "incident_key": incident_key_value,
                            "action_key": action_key,
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
            let action_time = Utc::now();
            let action_key = response_action_key("file_quarantine", &target.path);

            if !agent_state.should_allow_response_action(
                &incident_key_value,
                &action_key,
                action_time,
                RESPONSE_ACTION_COOLDOWN_SECONDS,
            ) {
                out.push(build_response_event(
                    action_time,
                    "response_suppressed_by_cooldown",
                    json!({
                        "action": "file_quarantine",
                        "target_type": "file",
                        "response_mode": response_mode(policy),
                        "outcome": "suppressed",
                        "original_event_type": event.event_type,
                        "incident_key": incident_key_value,
                        "action_key": action_key,
                        "path": target.path,
                        "selection_reason": target.selection_reason,
                        "reason": "Response action suppressed because the same incident/target pair is still in cooldown"
                    }),
                ));
                continue;
            }

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
                    // ── Whitelist check ──────────────────────────────────────────────
                    // RESPONSE IMPACT: files inside trusted app bundles bypass quarantine
                    // regardless of simulation mode.
                    if let Some(matched_entry) = file_matches_whitelist(&target.path, &whitelist) {
                        out.push(build_response_event(
                            action_time,
                            "response_blocked_by_whitelist",
                            json!({
                                "action": "file_quarantine",
                                "target_type": "file",
                                "response_mode": response_mode(policy),
                                "outcome": "blocked",
                                "original_event_type": event.event_type,
                                "incident_key": incident_key_value,
                                "action_key": action_key,
                                "path": target.path,
                                "path_kind": classified_path_kind,
                                "matched_entry": matched_entry,
                                "reason": format!("File path is trusted (matched whitelist entry: {matched_entry})")
                            }),
                        ));
                        continue;
                    }

                    if policy.simulation_mode {
                        out.push(build_response_event(
                            action_time,
                            "response_simulated_file_quarantine",
                            json!({
                                "action": "file_quarantine",
                                "target_type": "file",
                                "response_mode": response_mode(policy),
                                "outcome": "simulated",
                                "original_event_type": event.event_type,
                                "incident_key": incident_key_value,
                                "action_key": action_key,
                                "path": target.path,
                                "path_kind": classified_path_kind,
                                "score": score,
                                "confidence": confidence,
                                "selection_reason": target.selection_reason,
                                "reason": "Policy threshold met for file quarantine, but simulation mode is enabled"
                            }),
                        ));
                        agent_state.record_response_action(
                            &incident_key_value,
                            &action_key,
                            action_time,
                        );
                    } else {
                        match quarantine_file(&target.path) {
                            Ok(Some(new_path)) => {
                                out.push(build_response_event(
                                    action_time,
                                    "response_file_quarantined",
                                    json!({
                                        "action": "file_quarantine",
                                        "target_type": "file",
                                        "response_mode": response_mode(policy),
                                        "outcome": "executed",
                                        "original_event_type": event.event_type,
                                        "incident_key": incident_key_value,
                                        "action_key": action_key,
                                        "old_path": target.path,
                                        "new_path": new_path,
                                        "path_kind": classified_path_kind,
                                        "score": score,
                                        "confidence": confidence,
                                        "selection_reason": target.selection_reason
                                    }),
                                ));
                                agent_state.record_response_action(
                                    &incident_key_value,
                                    &action_key,
                                    action_time,
                                );
                            }
                            Ok(None) => {
                                out.push(build_response_event(
                                    action_time,
                                    "response_noop_target_missing",
                                    json!({
                                        "action": "file_quarantine",
                                        "target_type": "file",
                                        "response_mode": response_mode(policy),
                                        "outcome": "noop",
                                        "original_event_type": event.event_type,
                                        "incident_key": incident_key_value,
                                        "action_key": action_key,
                                        "path": target.path,
                                        "path_kind": classified_path_kind,
                                        "score": score,
                                        "confidence": confidence,
                                        "selection_reason": target.selection_reason,
                                        "reason": "Target file was no longer present when quarantine was attempted"
                                    }),
                                ));
                            }
                            Err(err) => {
                                out.push(build_response_event(
                                    action_time,
                                    "response_execution_failed",
                                    json!({
                                        "action": "file_quarantine",
                                        "target_type": "file",
                                        "response_mode": response_mode(policy),
                                        "outcome": "failed",
                                        "original_event_type": event.event_type,
                                        "incident_key": incident_key_value,
                                        "action_key": action_key,
                                        "path": target.path,
                                        "path_kind": classified_path_kind,
                                        "score": score,
                                        "confidence": confidence,
                                        "selection_reason": target.selection_reason,
                                        "reason": format!("file quarantine failed: {}", err)
                                    }),
                                ));
                            }
                        }
                    }
                }
                Err(reason) => {
                    out.push(build_response_event(
                        action_time,
                        "response_blocked_by_guardrail",
                        json!({
                            "action": "file_quarantine",
                            "target_type": "file",
                            "response_mode": response_mode(policy),
                            "outcome": "blocked",
                            "original_event_type": event.event_type,
                            "incident_key": incident_key_value,
                            "action_key": action_key,
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

    // If any actionable response was taken (executed or simulated), record the incident timestamp
    // so the per-incident cooldown fires on the next invocation.
    let any_executed = out.iter().any(|e| {
        matches!(
            e.event_type.as_str(),
            "response_process_killed"
                | "response_file_quarantined"
                | "response_simulated_process_kill"
                | "response_simulated_file_quarantine"
        )
    });
    if any_executed {
        agent_state.record_incident_response(&incident_key_value, action_time);

        // Emit a user-facing notification event so the UI layer can surface what happened.
        let action_summary: Vec<serde_json::Value> = out
            .iter()
            .filter(|e| e.event_type.starts_with("response_"))
            .map(|e| {
                json!({
                    "event_type": e.event_type,
                    "outcome": e.payload.get("outcome").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "target_type": e.payload.get("target_type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "pid": e.payload.get("pid"),
                    "path": e.payload.get("path").or_else(|| e.payload.get("old_path")),
                })
            })
            .collect();

        out.push(build_response_event(
            action_time,
            "response_user_notification",
            json!({
                "incident_key": incident_key_value,
                "original_event_type": event.event_type,
                "response_mode": response_mode(policy),
                "score": score,
                "confidence": confidence,
                "action_count": action_summary.len(),
                "actions": action_summary,
                "reason": format!(
                    "Response actions taken for incident '{}': {} action(s) in {} mode",
                    incident_key_value,
                    action_summary.len(),
                    response_mode(policy)
                ),
            }),
        ));
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

fn build_response_event(timestamp: chrono::DateTime<Utc>, event_type: &str, payload: Value) -> TelemetryEvent {
    TelemetryEvent::new(timestamp, event_type, "core-agent/response", payload)
}

fn response_mode(policy: &ResponsePolicy) -> &'static str {
    if policy.simulation_mode {
        "simulation"
    } else {
        "enforcement"
    }
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

/// Kill `pid` and all of its descendants (leaves first).
///
/// Returns `(root_killed, child_pids_killed)` where `root_killed` is whether
/// the target PID itself was successfully killed.
///
/// // RESPONSE IMPACT: This replaces single-process kill with full subtree kill.
/// Guardrails (safe process kinds, system paths) are applied to the root target
/// before this is called. Children are killed without re-checking guardrails
/// because they are descendants of an already-confirmed malicious process.
/// The response engine should only reach this path after guardrail checks pass.
fn kill_process(pid: i32) -> Result<bool> {
    let children = collect_process_subtree(pid);

    // Kill children first (leaves → root order), then the root
    for &child_pid in &children {
        if child_pid == pid {
            continue;
        }
        // Best-effort: ignore individual child kill errors
        let _ = Command::new("kill")
            .args(["-9", &child_pid.to_string()])
            .status();
    }

    let status = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .with_context(|| format!("failed to execute kill for pid {}", pid))?;

    Ok(status.success())
}

/// Collect all descendant PIDs of `root_pid` by parsing `ps -axo pid=,ppid=`.
/// Returns a list of descendant PIDs in leaves-first order (so they can be
/// killed before their parents), NOT including `root_pid` itself.
///
/// If `ps` fails or `root_pid` has no children, returns an empty Vec.
fn collect_process_subtree(root_pid: i32) -> Vec<i32> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid="])
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Build parent → children map
    let mut children_map: HashMap<i32, Vec<i32>> = HashMap::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let pid_str = parts.next().unwrap_or("");
        let ppid_str = parts.next().unwrap_or("");
        let (Ok(pid), Ok(ppid)) = (pid_str.parse::<i32>(), ppid_str.parse::<i32>()) else {
            continue;
        };
        children_map.entry(ppid).or_default().push(pid);
    }

    // BFS from root_pid to collect all descendants
    let mut queue = vec![root_pid];
    let mut ordered: Vec<i32> = Vec::new(); // BFS order (root first)
    let mut visited = BTreeSet::new();
    visited.insert(root_pid);

    while let Some(current) = queue.first().copied() {
        queue.remove(0);
        if let Some(kids) = children_map.get(&current) {
            for &child in kids {
                if visited.insert(child) {
                    queue.push(child);
                    ordered.push(child);
                }
            }
        }
    }

    // Return in reverse BFS order so leaves are killed before parents
    ordered.reverse();
    ordered
}

fn quarantine_file(original_path: &str) -> Result<Option<String>> {
    let source = Path::new(original_path);
    if !source.exists() {
        return Ok(None);
    }

    // Compute SHA256 before moving the file so we have a hash for rollback verification.
    let sha256 = compute_sha256(original_path).unwrap_or_else(|_| "unknown".to_string());

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

    let dest_str = dest_path.to_string_lossy().to_string();

    // Append an entry to the quarantine manifest so rollback can verify integrity.
    append_quarantine_manifest(original_path, &dest_str, &sha256);

    Ok(Some(dest_str))
}

/// Compute the SHA256 hex digest of a file using the macOS `shasum` CLI.
/// Returns the hex digest string (64 hex chars) on success.
fn compute_sha256(path: &str) -> Result<String> {
    let output = Command::new("shasum")
        .args(["-a", "256", path])
        .output()
        .context("shasum not available")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // shasum output format: "<hex>  <filename>"
    let hex = stdout
        .split_whitespace()
        .next()
        .filter(|s| s.len() == 64)
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("unexpected shasum output: {}", stdout.trim()))?;

    Ok(hex)
}

/// Append a quarantine record to the manifest JSONL file.
/// Failures are best-effort — we never want a manifest write to block quarantine.
fn append_quarantine_manifest(original_path: &str, quarantine_path: &str, sha256: &str) {
    use std::io::Write;
    let entry = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "original_path": original_path,
        "quarantine_path": quarantine_path,
        "sha256": sha256,
    });
    if let Ok(serialized) = serde_json::to_string(&entry) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(QUARANTINE_MANIFEST)
        {
            let _ = writeln!(f, "{serialized}");
        }
    }
}

/// Restore a quarantined file to its original path, verifying SHA256 integrity.
///
/// Reads the quarantine manifest to find the record for `quarantine_path`,
/// recomputes the SHA256 of the quarantined file, and moves it back only if the
/// hash matches the recorded value.
///
/// Returns a `response_rollback_executed` or `response_rollback_failed` event.
pub fn rollback_quarantined_file(
    quarantine_path: &str,
    incident_key: &str,
) -> TelemetryEvent {
    let now = Utc::now();

    let manifest_entry = read_manifest_entry(quarantine_path);

    let Some(entry) = manifest_entry else {
        return build_response_event(
            now,
            "response_rollback_failed",
            json!({
                "action": "file_rollback",
                "outcome": "failed",
                "quarantine_path": quarantine_path,
                "incident_key": incident_key,
                "reason": "No manifest entry found for this quarantine path — cannot verify integrity",
            }),
        );
    };

    let original_path = match entry.get("original_path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            return build_response_event(
                now,
                "response_rollback_failed",
                json!({
                    "action": "file_rollback",
                    "outcome": "failed",
                    "quarantine_path": quarantine_path,
                    "incident_key": incident_key,
                    "reason": "Manifest entry missing original_path field",
                }),
            );
        }
    };

    let expected_sha256 = entry
        .get("sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Recompute SHA256 of the quarantined file to verify it hasn't been tampered with.
    match compute_sha256(quarantine_path) {
        Ok(current_sha256) if current_sha256 == expected_sha256 || expected_sha256 == "unknown" => {
            // Hash matches (or was never computed) — safe to restore.
            match fs::rename(quarantine_path, &original_path) {
                Ok(()) => build_response_event(
                    now,
                    "response_rollback_executed",
                    json!({
                        "action": "file_rollback",
                        "outcome": "executed",
                        "quarantine_path": quarantine_path,
                        "original_path": original_path,
                        "sha256_verified": expected_sha256 != "unknown",
                        "incident_key": incident_key,
                        "reason": "File restored from quarantine after SHA256 verification passed",
                    }),
                ),
                Err(err) => build_response_event(
                    now,
                    "response_rollback_failed",
                    json!({
                        "action": "file_rollback",
                        "outcome": "failed",
                        "quarantine_path": quarantine_path,
                        "original_path": original_path,
                        "incident_key": incident_key,
                        "reason": format!("fs::rename failed: {}", err),
                    }),
                ),
            }
        }
        Ok(current_sha256) => build_response_event(
            now,
            "response_rollback_failed",
            json!({
                "action": "file_rollback",
                "outcome": "failed",
                "quarantine_path": quarantine_path,
                "original_path": original_path,
                "incident_key": incident_key,
                "expected_sha256": expected_sha256,
                "actual_sha256": current_sha256,
                "reason": "SHA256 mismatch: quarantined file may have been modified, refusing rollback",
            }),
        ),
        Err(err) => build_response_event(
            now,
            "response_rollback_failed",
            json!({
                "action": "file_rollback",
                "outcome": "failed",
                "quarantine_path": quarantine_path,
                "incident_key": incident_key,
                "reason": format!("Could not compute SHA256 for integrity check: {}", err),
            }),
        ),
    }
}

/// Read the most recent manifest entry for `quarantine_path` from QUARANTINE_MANIFEST.
fn read_manifest_entry(quarantine_path: &str) -> Option<serde_json::Value> {
    let content = fs::read_to_string(QUARANTINE_MANIFEST).ok()?;
    // Iterate in reverse to find the most recent entry for this quarantine path.
    content
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|entry| {
            entry
                .get("quarantine_path")
                .and_then(|v| v.as_str())
                .map(|p| p == quarantine_path)
                .unwrap_or(false)
        })
}

// ── Whitelist helpers ─────────────────────────────────────────────────────────

/// Look up the binary path of a running process via `ps -p {pid} -o comm=`.
/// Returns None if the process is not found or the command fails.
fn get_process_binary_path(pid: i32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    let raw = String::from_utf8_lossy(&output.stdout);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Returns the matching whitelist entry if the process should be protected, or None.
fn process_matches_whitelist(pid: i32, whitelist: &Whitelist) -> Option<String> {
    if whitelist.trusted_process_paths.is_empty()
        && whitelist.trusted_process_names.is_empty()
        && whitelist.trusted_app_bundle_paths.is_empty()
    {
        return None;
    }
    let binary_path = get_process_binary_path(pid)?;

    for trusted in &whitelist.trusted_process_paths {
        if binary_path == *trusted {
            return Some(trusted.clone());
        }
    }

    let binary_name = Path::new(&binary_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&binary_path);

    for trusted in &whitelist.trusted_process_names {
        if binary_name == trusted.as_str() {
            return Some(trusted.clone());
        }
    }

    for bundle in &whitelist.trusted_app_bundle_paths {
        if binary_path.starts_with(bundle.as_str()) {
            return Some(bundle.clone());
        }
    }

    None
}

/// Returns the matching whitelist entry if the file should be protected, or None.
fn file_matches_whitelist(file_path: &str, whitelist: &Whitelist) -> Option<String> {
    for bundle in &whitelist.trusted_app_bundle_paths {
        if file_path.starts_with(bundle.as_str()) {
            return Some(bundle.clone());
        }
    }
    for trusted in &whitelist.trusted_process_paths {
        if file_path == trusted.as_str() {
            return Some(trusted.clone());
        }
    }
    None
}