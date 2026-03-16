use crate::classify::{is_persistence_path, is_script_interpreter};
use crate::models::{AlertSeverity, FileEventRecord, ProcessInfo, TelemetryEvent};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

pub struct DetectionContext {
    pub recent_file_events: Vec<FileEventRecord>,
    pub recent_processes: Vec<ProcessInfo>,
    pub now: DateTime<Utc>,
}

pub fn evaluate_detections(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    if let Some(event) = detect_burst_file_activity(ctx) {
        detections.push(event);
    }

    detections.extend(detect_downloaded_file_execution(ctx));
    detections.extend(detect_interpreter_launch_from_downloads(ctx));
    detections.extend(detect_file_became_executable(ctx));
    detections.extend(detect_quarantined_file_activity(ctx));
    detections.extend(detect_persistence_artifact_touched(ctx));
    detections.extend(detect_suspicious_shell_chain(ctx));

    detections
}

pub fn alert_fingerprint(event: &TelemetryEvent) -> String {
    let payload = &event.payload;

    match event.event_type.as_str() {
        "alert_burst_file_activity" => {
            let directory = payload
                .get("details")
                .and_then(|d| d.get("directory"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, directory)
        }
        "alert_downloaded_file_executed" => {
            let command = payload
                .get("details")
                .and_then(|d| d.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let matched_download_path = payload
                .get("details")
                .and_then(|d| d.get("matched_download_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, command, matched_download_path)
        }
        "alert_interpreter_launch_from_downloads" => {
            let interpreter = payload
                .get("details")
                .and_then(|d| d.get("interpreter"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let matched_download_path = payload
                .get("details")
                .and_then(|d| d.get("matched_download_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, interpreter, matched_download_path)
        }
        "alert_file_became_executable" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_quarantined_file_activity" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_persistence_artifact_touched" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_suspicious_shell_chain" => {
            let parent_pid = payload
                .get("details")
                .and_then(|d| d.get("parent_pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let child_command = payload
                .get("details")
                .and_then(|d| d.get("child_command"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, parent_pid, child_command)
        }
        "alert_behavioral_incident" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        _ => format!("{}:{}", event.event_type, payload),
    }
}

fn detect_burst_file_activity(ctx: &DetectionContext) -> Option<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(15);
    let mut count_by_directory: HashMap<String, usize> = HashMap::new();

    for event in &ctx.recent_file_events {
        if event.timestamp < cutoff {
            continue;
        }

        let directory = parent_dir_string(&event.path);
        *count_by_directory.entry(directory).or_insert(0) += 1;
    }

    let (directory, count) = count_by_directory
        .into_iter()
        .max_by_key(|(_, count)| *count)?;

    if count < 25 {
        return None;
    }

    Some(build_alert(
        ctx.now,
        "alert_burst_file_activity",
        AlertSeverity::Medium,
        "file_activity",
        "Unusually high file activity in a short time window",
        json!({
            "directory": directory,
            "events_in_last_15_seconds": count
        }),
    ))
}

fn detect_downloaded_file_execution(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(120);

    let recent_download_paths: Vec<String> = ctx
        .recent_file_events
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .filter(|event| event.path.contains("/Downloads/"))
        .map(|event| event.path.clone())
        .collect();

    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        let process_text = format!("{} {}", process.command, process.args);

        for download_path in &recent_download_paths {
            if process_text.contains(download_path) || process.command == *download_path {
                detections.push(build_alert(
                    ctx.now,
                    "alert_downloaded_file_executed",
                    AlertSeverity::High,
                    "execution",
                    "A recently downloaded file appears to have been executed",
                    json!({
                        "pid": process.pid,
                        "ppid": process.ppid,
                        "command": process.command,
                        "args": process.args,
                        "process_kind": process.process_kind,
                        "command_path_kind": process.command_path_kind,
                        "matched_download_path": download_path,
                        "parent_command": process.parent_command,
                        "parent_args": process.parent_args,
                        "parent_process_kind": process.parent_process_kind,
                        "parent_command_path_kind": process.parent_command_path_kind
                    }),
                ));
                break;
            }
        }
    }

    detections
}

fn detect_interpreter_launch_from_downloads(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(120);

    let recent_download_paths: Vec<String> = ctx
        .recent_file_events
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .filter(|event| event.path.contains("/Downloads/"))
        .map(|event| event.path.clone())
        .collect();

    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        if !is_script_interpreter(&process.command) {
            continue;
        }

        let process_text = format!("{} {}", process.command, process.args);

        for download_path in &recent_download_paths {
            if process_text.contains(download_path) {
                detections.push(build_alert(
                    ctx.now,
                    "alert_interpreter_launch_from_downloads",
                    AlertSeverity::High,
                    "script_execution",
                    "A script interpreter appears to have launched content from Downloads",
                    json!({
                        "pid": process.pid,
                        "ppid": process.ppid,
                        "interpreter": process.command,
                        "args": process.args,
                        "process_kind": process.process_kind,
                        "command_path_kind": process.command_path_kind,
                        "matched_download_path": download_path,
                        "file_extension": file_extension(download_path),
                        "parent_command": process.parent_command,
                        "parent_args": process.parent_args,
                        "parent_process_kind": process.parent_process_kind,
                        "parent_command_path_kind": process.parent_command_path_kind
                    }),
                ));
                break;
            }
        }
    }

    detections
}

fn detect_file_became_executable(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(120);

    ctx.recent_file_events
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .filter(|event| event.kind == "file_became_executable")
        .map(|event| {
            let severity = if event.path.contains("/Downloads/") {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            };

            build_alert(
                ctx.now,
                "alert_file_became_executable",
                severity,
                "permissions",
                "A file gained executable permissions",
                json!({
                    "path": event.path,
                    "directory": parent_dir_string(&event.path),
                    "in_downloads": event.path.contains("/Downloads/"),
                    "file_extension": file_extension(&event.path)
                }),
            )
        })
        .collect()
}

fn detect_quarantined_file_activity(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(120);

    ctx.recent_file_events
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .filter(|event| event.path.contains("/Downloads/"))
        .filter(|event| event.has_quarantine)
        .filter(|event| {
            event.kind == "file_created"
                || event.kind == "file_modified"
                || event.kind == "file_gained_quarantine"
        })
        .filter(|event| is_high_signal_download_path(&event.path))
        .map(|event| {
            let severity = quarantine_severity(event);

            build_alert(
                ctx.now,
                "alert_quarantined_file_activity",
                severity,
                "quarantine",
                "A high-signal Downloads item carries macOS quarantine metadata",
                json!({
                    "path": event.path,
                    "event_kind": event.kind,
                    "directory": parent_dir_string(&event.path),
                    "file_extension": file_extension(&event.path),
                    "is_executable": event.is_executable,
                    "size_bytes": event.size_bytes,
                    "quarantine_value": event.quarantine_value,
                    "top_level_download_item": is_top_level_download_item(&event.path)
                }),
            )
        })
        .collect()
}

fn detect_persistence_artifact_touched(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(120);

    ctx.recent_file_events
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .filter(|event| event.kind == "file_created" || event.kind == "file_modified")
        .filter(|event| is_persistence_path(&event.path))
        .map(|event| {
            build_alert(
                ctx.now,
                "alert_persistence_artifact_touched",
                AlertSeverity::High,
                "persistence",
                "A file associated with a persistence mechanism was created or modified",
                json!({
                    "path": event.path,
                    "event_kind": event.kind,
                    "directory": parent_dir_string(&event.path),
                    "file_extension": file_extension(&event.path),
                    "is_executable": event.is_executable,
                    "has_quarantine": event.has_quarantine
                }),
            )
        })
        .collect()
}

fn detect_suspicious_shell_chain(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(120);

    let recent_download_paths: Vec<String> = ctx
        .recent_file_events
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .filter(|event| event.path.contains("/Downloads/"))
        .map(|event| event.path.clone())
        .collect();

    let mut interpreter_parents: HashMap<i32, (&ProcessInfo, String)> = HashMap::new();

    for process in &ctx.recent_processes {
        if !is_script_interpreter(&process.command) {
            continue;
        }

        let process_text = format!("{} {}", process.command, process.args);

        for download_path in &recent_download_paths {
            if process_text.contains(download_path) {
                interpreter_parents.insert(process.pid, (process, download_path.clone()));
                break;
            }
        }
    }

    let mut detections = Vec::new();

    for child in &ctx.recent_processes {
        if let Some((parent, matched_download_path)) = interpreter_parents.get(&child.ppid) {
            if child.pid == parent.pid {
                continue;
            }

            if is_boring_shell_child(&child.command) {
                continue;
            }

            detections.push(build_alert(
                ctx.now,
                "alert_suspicious_shell_chain",
                AlertSeverity::High,
                "process_chain",
                "A script launched from Downloads spawned a follow-on child process",
                json!({
                    "parent_pid": parent.pid,
                    "parent_command": parent.command,
                    "parent_args": parent.args,
                    "parent_process_kind": parent.process_kind,
                    "parent_command_path_kind": parent.command_path_kind,
                    "child_pid": child.pid,
                    "child_command": child.command,
                    "child_args": child.args,
                    "child_process_kind": child.process_kind,
                    "child_command_path_kind": child.command_path_kind,
                    "matched_download_path": matched_download_path,
                    "child_parent_command": child.parent_command,
                    "child_parent_args": child.parent_args
                }),
            ));
        }
    }

    detections
}

fn quarantine_severity(event: &FileEventRecord) -> AlertSeverity {
    let ext = file_extension(&event.path);

    if event.is_executable || is_risky_download_extension(&ext) {
        AlertSeverity::High
    } else {
        AlertSeverity::Medium
    }
}

fn is_high_signal_download_path(path: &str) -> bool {
    if is_top_level_download_item(path) {
        return true;
    }

    let lower = path.to_ascii_lowercase();

    lower.ends_with(".app")
        || lower.ends_with(".pkg")
        || lower.ends_with(".dmg")
        || lower.ends_with(".zip")
        || lower.ends_with(".xip")
        || lower.ends_with(".sh")
        || lower.ends_with(".command")
        || lower.ends_with(".py")
        || lower.ends_with(".js")
        || lower.ends_with(".scpt")
}

fn is_top_level_download_item(path: &str) -> bool {
    let p = Path::new(path);
    let components: Vec<String> = p
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    if let Some(downloads_index) = components.iter().position(|c| c == "Downloads") {
        let remaining = components.len().saturating_sub(downloads_index + 1);
        return remaining == 1;
    }

    false
}

fn is_risky_download_extension(ext: &str) -> bool {
    matches!(
        ext,
        "app" | "pkg" | "dmg" | "zip" | "xip" | "sh" | "command" | "py" | "js" | "scpt" | "jar" | "bin"
    )
}

fn is_boring_shell_child(command: &str) -> bool {
    let filename = Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();

    matches!(filename.as_str(), "ps")
}

fn file_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn build_alert(
    now: DateTime<Utc>,
    event_type: &str,
    severity: AlertSeverity,
    category: &str,
    reason: &str,
    details: serde_json::Value,
) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        event_type,
        "core-agent/detections",
        json!({
            "severity": severity.as_str(),
            "score": severity.score(),
            "category": category,
            "reason": reason,
            "details": details
        }),
    )
}

fn parent_dir_string(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string())
}