use crate::classify::classify_path;
use crate::models::{AlertSeverity, TelemetryEvent};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone)]
struct IncidentAccumulator {
    grouping_key: String,
    supporting_events: Vec<String>,
    signal_set: HashSet<String>,
    related_paths: BTreeSet<String>,
    involved_pids: BTreeSet<i32>,
    chain_root_pid: Option<i32>,
    chain_root_command: Option<String>,
    chosen_command: Option<String>,
    chosen_process_kind: Option<String>,
    chosen_parent_process_kind: Option<String>,
    attack_chain_length: usize,
}

pub fn aggregate_incidents(detections: &[TelemetryEvent], now: DateTime<Utc>) -> Vec<TelemetryEvent> {
    let mut groups: HashMap<String, IncidentAccumulator> = HashMap::new();

    for detection in detections {
        let grouping_key = extract_grouping_key(detection);

        let entry = groups
            .entry(grouping_key.clone())
            .or_insert_with(|| IncidentAccumulator {
                grouping_key,
                supporting_events: Vec::new(),
                signal_set: HashSet::new(),
                related_paths: BTreeSet::new(),
                involved_pids: BTreeSet::new(),
                chain_root_pid: None,
                chain_root_command: None,
                chosen_command: None,
                chosen_process_kind: None,
                chosen_parent_process_kind: None,
                attack_chain_length: 1,
            });

        if entry.signal_set.insert(detection.event_type.clone()) {
            entry.supporting_events.push(detection.event_type.clone());
        }

        if let Some(path) = extract_primary_path(detection) {
            entry.related_paths.insert(path);
        }

        for path in extract_related_paths(detection) {
            entry.related_paths.insert(path);
        }

        if let Some(pid) = extract_pid(detection) {
            entry.involved_pids.insert(pid);
        }

        if let Some(pid) = extract_child_pid(detection) {
            entry.involved_pids.insert(pid);
        }

        if let Some(pid) = extract_parent_pid(detection) {
            entry.involved_pids.insert(pid);
        }

        if entry.chain_root_pid.is_none() {
            entry.chain_root_pid = extract_chain_root_pid(detection);
        }

        if entry.chain_root_command.is_none() {
            entry.chain_root_command = extract_chain_root_command(detection);
        }

        if entry.chosen_command.is_none() {
            entry.chosen_command = extract_command(detection);
        }

        if entry.chosen_process_kind.is_none() {
            entry.chosen_process_kind = extract_process_kind(detection);
        }

        if entry.chosen_parent_process_kind.is_none() {
            entry.chosen_parent_process_kind = extract_parent_process_kind(detection);
        }

        entry.attack_chain_length = entry
            .attack_chain_length
            .max(extract_attack_chain_length(detection).unwrap_or(1));
    }

    let mut incidents = Vec::new();

    for (_, acc) in groups {
        if let Some(event) = build_incident(acc, now) {
            incidents.push(event);
        }
    }

    incidents
}

fn build_incident(acc: IncidentAccumulator, now: DateTime<Utc>) -> Option<TelemetryEvent> {
    let has_download_exec = acc.signal_set.contains("alert_downloaded_file_executed");
    let has_interpreter_downloads = acc
        .signal_set
        .contains("alert_interpreter_launch_from_downloads");
    let has_shell_chain = acc.signal_set.contains("alert_suspicious_shell_chain");
    let has_exec_perm = acc.signal_set.contains("alert_file_became_executable");
    let has_command_pattern = acc.signal_set.contains("alert_command_pattern_abuse");
    let has_interpreter_abuse = acc.signal_set.contains("alert_interpreter_abuse");
    let has_follow_on_binary = acc
        .signal_set
        .contains("alert_interpreter_spawned_follow_on_binary");
    let has_persistence = acc.signal_set.contains("alert_persistence_artifact_touched");
    let has_suspicious_persistence_chain = acc
        .signal_set
        .contains("alert_suspicious_persistence_chain");
    let has_downloaded_installer = acc
        .signal_set
        .contains("alert_downloaded_installer_activity");

    let distinct_signals = acc.signal_set.len();

    let (severity, score, reason) = if has_suspicious_persistence_chain
        && (has_command_pattern || has_interpreter_abuse)
    {
        (
            AlertSeverity::Critical,
            97u8,
            "A suspicious execution chain appears to have established or modified persistence",
        )
    } else if has_downloaded_installer && has_persistence {
        (
            AlertSeverity::Critical,
            95u8,
            "Downloaded installer-like activity was followed by persistence artifact modification",
        )
    } else if has_command_pattern && has_follow_on_binary {
        (
            AlertSeverity::Critical,
            96u8,
            "Suspicious command execution patterns escalated into a follow-on process chain",
        )
    } else if has_download_exec && has_interpreter_abuse && has_follow_on_binary {
        (
            AlertSeverity::Critical,
            94u8,
            "Downloaded content executed through an interpreter and produced a second-stage child process",
        )
    } else if has_download_exec && has_interpreter_downloads && has_shell_chain && has_exec_perm {
        (
            AlertSeverity::Critical,
            95u8,
            "Downloaded content became executable, was launched through an interpreter, and spawned child processes",
        )
    } else if has_download_exec && has_interpreter_downloads && has_shell_chain {
        (
            AlertSeverity::Critical,
            92u8,
            "Downloaded content was launched through an interpreter and spawned follow-on child processes",
        )
    } else if has_persistence && has_interpreter_abuse {
        (
            AlertSeverity::High,
            88u8,
            "Interpreter-driven execution chain touched a persistence artifact",
        )
    } else if distinct_signals >= 3 && acc.attack_chain_length >= 2 {
        (
            AlertSeverity::High,
            86u8,
            "Multiple correlated behavioral signals were observed in a single execution chain",
        )
    } else {
        return None;
    };

    let related_paths: Vec<String> = acc.related_paths.iter().cloned().collect();
    let primary_path = related_paths.first().cloned();
    let path_kind = primary_path
        .as_deref()
        .map(classify_path)
        .unwrap_or_else(|| "unknown".to_string());

    Some(TelemetryEvent::new(
        now,
        "alert_behavioral_incident",
        "core-agent/incidents",
        json!({
            "severity": severity.as_str(),
            "score": score,
            "category": "behavioral_incident",
            "reason": reason,
            "details": {
                "grouping_key": acc.grouping_key,
                "primary_path": primary_path,
                "related_paths": related_paths,
                "path_kind": path_kind,
                "chain_root_pid": acc.chain_root_pid,
                "chain_root_command": acc.chain_root_command,
                "involved_pids": acc.involved_pids.iter().copied().collect::<Vec<i32>>(),
                "chosen_command": acc.chosen_command,
                "chosen_process_kind": acc.chosen_process_kind,
                "chosen_parent_process_kind": acc.chosen_parent_process_kind,
                "supporting_events": acc.supporting_events,
                "signal_count": acc.signal_set.len(),
                "attack_chain_length": acc.attack_chain_length
            }
        }),
    ))
}

fn extract_grouping_key(event: &TelemetryEvent) -> String {
    if let Some(chain_root_pid) = extract_chain_root_pid(event) {
        return format!("chain_root_pid:{chain_root_pid}");
    }

    if let Some(path) = extract_primary_path(event) {
        return format!("path:{path}");
    }

    format!("event_type:{}", event.event_type)
}

fn extract_primary_path(event: &TelemetryEvent) -> Option<String> {
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
        .or_else(|| {
            details
                .get("persistence_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            details
                .get("primary_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn extract_related_paths(event: &TelemetryEvent) -> Vec<String> {
    let Some(details) = event.payload.get("details") else {
        return Vec::new();
    };

    details
        .get("related_paths")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

fn extract_pid(event: &TelemetryEvent) -> Option<i32> {
    let details = event.payload.get("details")?;
    details
        .get("pid")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
}

fn extract_child_pid(event: &TelemetryEvent) -> Option<i32> {
    let details = event.payload.get("details")?;
    details
        .get("child_pid")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
}

fn extract_parent_pid(event: &TelemetryEvent) -> Option<i32> {
    let details = event.payload.get("details")?;
    details
        .get("parent_pid")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
}

fn extract_chain_root_pid(event: &TelemetryEvent) -> Option<i32> {
    let details = event.payload.get("details")?;
    details
        .get("chain_root_pid")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
}

fn extract_chain_root_command(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;
    details
        .get("chain_root_command")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn extract_command(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("child_command")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            details
                .get("command")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            details
                .get("interpreter")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn extract_process_kind(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("child_process_kind")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            details
                .get("process_kind")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn extract_parent_process_kind(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;
    details
        .get("parent_process_kind")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn extract_attack_chain_length(event: &TelemetryEvent) -> Option<usize> {
    let details = event.payload.get("details")?;
    details
        .get("attack_chain_length")
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
}