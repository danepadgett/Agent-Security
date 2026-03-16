use crate::classify::classify_path;
use crate::models::{AlertSeverity, TelemetryEvent};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
struct IncidentAccumulator {
    path: String,
    supporting_events: Vec<String>,
    signal_set: HashSet<String>,
    pid: Option<i32>,
    child_pid: Option<i32>,
    parent_pid: Option<i32>,
    chosen_command: Option<String>,
    chosen_process_kind: Option<String>,
    chosen_parent_process_kind: Option<String>,
}

pub fn aggregate_incidents(
    detections: &[TelemetryEvent],
    now: DateTime<Utc>,
) -> Vec<TelemetryEvent> {
    let mut groups: HashMap<String, IncidentAccumulator> = HashMap::new();

    for detection in detections {
        let Some(path) = extract_path(detection) else {
            continue;
        };

        let entry = groups.entry(path.clone()).or_insert_with(|| IncidentAccumulator {
            path: path.clone(),
            supporting_events: Vec::new(),
            signal_set: HashSet::new(),
            pid: None,
            child_pid: None,
            parent_pid: None,
            chosen_command: None,
            chosen_process_kind: None,
            chosen_parent_process_kind: None,
        });

        if !entry.signal_set.contains(&detection.event_type) {
            entry.supporting_events.push(detection.event_type.clone());
            entry.signal_set.insert(detection.event_type.clone());
        }

        if entry.pid.is_none() {
            entry.pid = extract_pid(detection);
        }

        if entry.child_pid.is_none() {
            entry.child_pid = extract_child_pid(detection);
        }

        if entry.parent_pid.is_none() {
            entry.parent_pid = extract_parent_pid(detection);
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
    let has_exec = acc.signal_set.contains("alert_downloaded_file_executed");
    let has_interpreter = acc
        .signal_set
        .contains("alert_interpreter_launch_from_downloads");
    let has_chain = acc.signal_set.contains("alert_suspicious_shell_chain");
    let has_exec_perm = acc.signal_set.contains("alert_file_became_executable");

    let (severity, score, reason) = if has_exec && has_interpreter && has_chain && has_exec_perm {
        (
            AlertSeverity::Critical,
            95u8,
            "Downloaded content became executable, was launched through an interpreter, and spawned child processes",
        )
    } else if has_exec && has_interpreter && has_chain {
        (
            AlertSeverity::Critical,
            92u8,
            "Downloaded content was launched through an interpreter and spawned follow-on child processes",
        )
    } else if has_exec && has_interpreter && has_exec_perm {
        (
            AlertSeverity::Critical,
            90u8,
            "Downloaded content became executable and was then launched through an interpreter",
        )
    } else {
        return None;
    };

    let chosen_pid = acc.child_pid.or(acc.pid);
    let path_kind = classify_path(&acc.path);

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
                "path": acc.path,
                "path_kind": path_kind,
                "pid": chosen_pid,
                "child_pid": acc.child_pid,
                "parent_pid": acc.parent_pid,
                "chosen_command": acc.chosen_command,
                "chosen_process_kind": acc.chosen_process_kind,
                "chosen_parent_process_kind": acc.chosen_parent_process_kind,
                "supporting_events": acc.supporting_events,
                "signal_count": acc.signal_set.len()
            }
        }),
    ))
}

fn extract_path(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("matched_download_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| details.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()))
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

fn extract_command(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("child_command")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| details.get("command").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .or_else(|| details.get("interpreter").and_then(|v| v.as_str()).map(|s| s.to_string()))
}

fn extract_process_kind(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("child_process_kind")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| details.get("process_kind").and_then(|v| v.as_str()).map(|s| s.to_string()))
}

fn extract_parent_process_kind(event: &TelemetryEvent) -> Option<String> {
    let details = event.payload.get("details")?;

    details
        .get("parent_process_kind")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}