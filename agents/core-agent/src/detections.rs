use crate::classify::{
    is_benign_admin_tool_command, is_benign_developer_tool_command, is_persistence_path,
    is_persistence_tool_command, is_script_interpreter,
};
use crate::execution_graph::{ExecutionChain, ExecutionGraphSnapshot};
use crate::lineage::LineageSnapshot;
use crate::models::{AlertSeverity, FileEventRecord, ProcessInfo, TelemetryEvent};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use crate::baseline::BaselineSnapshot;
use crate::provenance::ArtifactProvenanceSnapshot;

pub struct DetectionContext {
    pub recent_file_events: Vec<FileEventRecord>,
    pub current_processes: Vec<ProcessInfo>,
    pub recent_processes: Vec<ProcessInfo>,
    pub execution_graph: ExecutionGraphSnapshot,
    pub lineage: LineageSnapshot,
    pub provenance: ArtifactProvenanceSnapshot,
    pub baseline: BaselineSnapshot,
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
    detections.extend(detect_command_pattern_abuse(ctx));
    detections.extend(detect_interpreter_abuse(ctx));
    detections.extend(detect_interpreter_spawned_follow_on_binary(ctx));
    detections.extend(detect_downloader_url_execution(ctx));
    detections.extend(detect_browser_ancestor_downloader_chain(ctx));
    detections.extend(detect_persistence_tooling_activity(ctx));
    detections.extend(detect_suspicious_persistence_chain(ctx));
    detections.extend(detect_downloaded_installer_activity(ctx));

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
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let matched_download_path = payload
                .get("details")
                .and_then(|d| d.get("matched_download_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, matched_download_path)
        }
        "alert_interpreter_launch_from_downloads" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let matched_download_path = payload
                .get("details")
                .and_then(|d| d.get("matched_download_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, matched_download_path)
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
        "alert_persistence_artifact_touched"
        | "alert_suspicious_persistence_chain"
        | "alert_persistence_tooling_activity" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .or_else(|| payload.get("details").and_then(|d| d.get("persistence_path")))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_suspicious_shell_chain"
        | "alert_interpreter_spawned_follow_on_binary"
        | "alert_downloaded_installer_activity"
        | "alert_browser_ancestor_downloader_chain" => {
            let parent_pid = payload
                .get("details")
                .and_then(|d| d.get("parent_pid"))
                .or_else(|| payload.get("details").and_then(|d| d.get("pid")))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let child_command = payload
                .get("details")
                .and_then(|d| d.get("child_command"))
                .or_else(|| payload.get("details").and_then(|d| d.get("command")))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, parent_pid, child_command)
        }
        "alert_command_pattern_abuse" | "alert_downloader_url_execution" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            format!("{}:{}", event.event_type, pid)
        }
        "alert_interpreter_abuse" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            format!("{}:{}", event.event_type, pid)
        }
        "alert_behavioral_incident" => {
            let chain_root_pid = payload
                .get("details")
                .and_then(|d| d.get("chain_root_pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            format!("{}:{}", event.event_type, chain_root_pid)
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

    let (directory, count) = count_by_directory.into_iter().max_by_key(|(_, count)| *count)?;
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
            "events_in_last_15_seconds": count,
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
        if is_benign_process_context(process) {
            continue;
        }

        let process_text = format!("{} {}", process.command, process.args);

        for download_path in &recent_download_paths {
            if process_text.contains(download_path) || process.command == *download_path {
                let mut details = json!({
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
                    "parent_command_path_kind": process.parent_command_path_kind,
                    "behavior": process.behavior,
                });

                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                detections.push(build_alert(
                    ctx.now,
                    "alert_downloaded_file_executed",
                    AlertSeverity::High,
                    "execution",
                    "A recently downloaded file appears to have been executed",
                    details,
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
        if !is_script_interpreter(&process.command) || is_benign_process_context(process) {
            continue;
        }

        let process_text = format!("{} {}", process.command, process.args);

        for download_path in &recent_download_paths {
            if process_text.contains(download_path) {
                let mut details = json!({
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
                    "parent_command_path_kind": process.parent_command_path_kind,
                    "behavior": process.behavior,
                });

                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                detections.push(build_alert(
                    ctx.now,
                    "alert_interpreter_launch_from_downloads",
                    AlertSeverity::High,
                    "script_execution",
                    "A script interpreter appears to have launched content from Downloads",
                    details,
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
                    "file_extension": file_extension(&event.path),
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
                    "top_level_download_item": is_top_level_download_item(&event.path),
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
                    "has_quarantine": event.has_quarantine,
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
        if !is_script_interpreter(&process.command) || is_benign_process_context(process) {
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
            if child.pid == parent.pid || is_boring_shell_child(&child.command) {
                continue;
            }

            let mut details = json!({
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
                "child_parent_args": child.parent_args,
            });

            merge_chain_details(&mut details, chain_details(child.pid, ctx));

            detections.push(build_alert(
                ctx.now,
                "alert_suspicious_shell_chain",
                AlertSeverity::High,
                "process_chain",
                "A script launched from Downloads spawned a follow-on child process",
                details,
            ));
        }
    }

    detections
}

fn detect_command_pattern_abuse(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        if process.behavior.suspicious_command_patterns.is_empty() {
            continue;
        }

        if should_suppress_command_pattern_detection(process) {
            continue;
        }

        let severity = if process
            .behavior
            .suspicious_command_patterns
            .iter()
            .any(|pattern| pattern == "network_tool_piped_to_shell")
        {
            AlertSeverity::Critical
        } else if process
            .behavior
            .suspicious_command_patterns
            .iter()
            .any(|pattern| {
                pattern == "launchctl_persistence_operation"
                    || pattern == "crontab_persistence_operation"
                    || pattern == "installer_pkg_execution"
                    || pattern == "open_executable_candidate"
                    || pattern == "network_download_with_url"
            }) {
            AlertSeverity::High
        } else {
            AlertSeverity::High
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "command_path_kind": process.command_path_kind,
            "matched_patterns": process.behavior.suspicious_command_patterns,
            "referenced_paths": process.behavior.referenced_paths,
            "referenced_urls": process.behavior.referenced_urls,
            "behavior": process.behavior,
            "parent_command": process.parent_command,
            "parent_args": process.parent_args,
            "parent_process_kind": process.parent_process_kind,
        });

        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_command_pattern_abuse",
            severity,
            "command_pattern",
            "A process command line matched suspicious execution patterns",
            details,
        ));
    }

    detections
}

fn detect_interpreter_abuse(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        if !is_script_interpreter(&process.command) {
            continue;
        }

        if should_suppress_interpreter_detection(process) {
            continue;
        }

        let high_signal = process.behavior.has_inline_code_execution
            || process.behavior.references_downloads_path
            || process.behavior.references_script_file
            || process.behavior.references_persistence_path
            || process.behavior.references_url;

        if !high_signal {
            continue;
        }

        let severity = if process.behavior.references_downloads_path
            && process.behavior.references_script_file
        {
            AlertSeverity::High
        } else if process.behavior.references_persistence_path || process.behavior.references_url {
            AlertSeverity::High
        } else {
            AlertSeverity::Medium
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "interpreter": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "command_path_kind": process.command_path_kind,
            "behavior": process.behavior,
            "parent_command": process.parent_command,
            "parent_args": process.parent_args,
            "parent_process_kind": process.parent_process_kind,
        });

        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_interpreter_abuse",
            severity,
            "interpreter_abuse",
            "A script interpreter was launched with high-signal execution characteristics",
            details,
        ));
    }

    detections
}

fn detect_interpreter_spawned_follow_on_binary(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for child in &ctx.recent_processes {
        let Some(parent_node) = ctx.execution_graph.nodes.get(&child.ppid) else {
            continue;
        };

        let parent = &parent_node.process;

        if !is_script_interpreter(&parent.command) || should_suppress_interpreter_detection(parent) {
            continue;
        }

        let suspicious_parent = parent.behavior.has_inline_code_execution
            || parent.behavior.references_downloads_path
            || parent.behavior.references_url
            || !parent.behavior.suspicious_command_patterns.is_empty();

        if !suspicious_parent || is_boring_shell_child(&child.command) {
            continue;
        }

        let mut details = json!({
            "parent_pid": parent.pid,
            "parent_command": parent.command,
            "parent_args": parent.args,
            "parent_process_kind": parent.process_kind,
            "child_pid": child.pid,
            "child_command": child.command,
            "child_args": child.args,
            "child_process_kind": child.process_kind,
            "child_command_path_kind": child.command_path_kind,
            "parent_behavior": parent.behavior,
            "child_behavior": child.behavior,
        });

        merge_chain_details(&mut details, chain_details(child.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_interpreter_spawned_follow_on_binary",
            AlertSeverity::High,
            "process_chain",
            "A suspicious interpreter process spawned a follow-on child process",
            details,
        ));
    }

    detections
}

fn detect_downloader_url_execution(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        if should_suppress_command_pattern_detection(process) {
            continue;
        }

        let downloader_like = process.behavior.uses_network_download_tool
            || process.behavior.downloader_family.is_some();

        if !(downloader_like && process.behavior.references_url) {
            continue;
        }

        let severity = if process.behavior.references_downloads_path
            || process.behavior.references_executable_candidate
        {
            AlertSeverity::High
        } else {
            AlertSeverity::Medium
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "command_path_kind": process.command_path_kind,
            "downloader_family": process.behavior.downloader_family,
            "referenced_urls": process.behavior.referenced_urls,
            "behavior": process.behavior,
            "parent_command": process.parent_command,
            "parent_args": process.parent_args,
            "parent_process_kind": process.parent_process_kind,
        });

        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_downloader_url_execution",
            severity,
            "network_download",
            "A downloader-like process referenced one or more URLs during execution",
            details,
        ));
    }

    detections
}

fn detect_browser_ancestor_downloader_chain(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        if !ctx.lineage.has_browser_ancestor(process.pid, 6) {
            continue;
        }

        let downloader_like = process.behavior.uses_network_download_tool
            || process.behavior.downloader_family.is_some()
            || process.behavior.references_url;

        if !downloader_like || should_suppress_command_pattern_detection(process) {
            continue;
        }

        let nearest_browser = ctx
            .lineage
            .nearest_browser_ancestor_command(process.pid, 6)
            .unwrap_or_else(|| "unknown_browser".to_string());

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "command_path_kind": process.command_path_kind,
            "referenced_urls": process.behavior.referenced_urls,
            "nearest_browser_ancestor": nearest_browser,
            "behavior": process.behavior,
            "parent_command": process.parent_command,
            "parent_args": process.parent_args,
            "parent_process_kind": process.parent_process_kind,
        });

        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_browser_ancestor_downloader_chain",
            AlertSeverity::High,
            "browser_origin_download",
            "A browser-originating ancestry chain led into downloader-like execution",
            details,
        ));
    }

    detections
}

fn detect_persistence_tooling_activity(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        if !is_persistence_tool_command(&process.command) {
            continue;
        }

        if should_suppress_persistence_tool_detection(process) {
            continue;
        }

        let matched_patterns = process
            .behavior
            .suspicious_command_patterns
            .iter()
            .filter(|pattern| {
                matches!(
                    pattern.as_str(),
                    "launchctl_persistence_operation"
                        | "crontab_persistence_operation"
                        | "persistence_path_reference"
                )
            })
            .cloned()
            .collect::<Vec<String>>();

        if matched_patterns.is_empty() && !process.behavior.references_persistence_path {
            continue;
        }

        let severity = if process.behavior.references_downloads_path {
            AlertSeverity::Critical
        } else {
            AlertSeverity::High
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "command_path_kind": process.command_path_kind,
            "matched_patterns": matched_patterns,
            "behavior": process.behavior,
            "parent_command": process.parent_command,
            "parent_args": process.parent_args,
            "parent_process_kind": process.parent_process_kind,
            "persistence_path": process.behavior.referenced_paths.iter().find(|path| is_persistence_path(path)).cloned(),
        });

        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_persistence_tooling_activity",
            severity,
            "persistence_tooling",
            "Persistence-oriented tooling activity was observed in process execution",
            details,
        ));
    }

    detections
}

fn detect_suspicious_persistence_chain(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(180);
    let persistence_events: Vec<&FileEventRecord> = ctx
        .recent_file_events
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .filter(|event| event.kind == "file_created" || event.kind == "file_modified")
        .filter(|event| is_persistence_path(&event.path))
        .collect();

    let mut detections = Vec::new();

    for persistence_event in persistence_events {
        for process in &ctx.recent_processes {
            if should_suppress_persistence_tool_detection(process) {
                continue;
            }

            let chain = ctx.execution_graph.chain_for_pid(process.pid, 6);

            let Some(chain) = chain else {
                continue;
            };

            let chain_refs_persistence =
                chain.related_paths.iter().any(|path| path == &persistence_event.path)
                    || process
                        .behavior
                        .referenced_paths
                        .iter()
                        .any(|path| path == &persistence_event.path)
                    || process.behavior.references_persistence_path;

            let suspicious_chain = process.behavior.references_downloads_path
                || process.behavior.has_inline_code_execution
                || process.behavior.references_url
                || !process.behavior.suspicious_command_patterns.is_empty()
                || chain.attack_chain_length >= 2;

            if !(chain_refs_persistence && suspicious_chain) {
                continue;
            }

            let severity = if process.behavior.references_downloads_path
                || process.behavior.references_url
                || process
                    .behavior
                    .suspicious_command_patterns
                    .iter()
                    .any(|p| p == "launchctl_persistence_operation" || p == "crontab_persistence_operation")
            {
                AlertSeverity::Critical
            } else {
                AlertSeverity::High
            };

            let mut details = json!({
                "persistence_path": persistence_event.path,
                "event_kind": persistence_event.kind,
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "command_path_kind": process.command_path_kind,
                "behavior": process.behavior,
                "parent_command": process.parent_command,
                "parent_args": process.parent_args,
                "parent_process_kind": process.parent_process_kind,
            });

            merge_chain_details(&mut details, execution_chain_json(&chain, &ctx.lineage, process.pid));

            detections.push(build_alert(
                ctx.now,
                "alert_suspicious_persistence_chain",
                severity,
                "persistence",
                "A suspicious execution chain appears to have referenced or modified a persistence artifact",
                details,
            ));
        }
    }

    detections
}

fn detect_downloaded_installer_activity(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        let patterns = &process.behavior.suspicious_command_patterns;
        let installer_like = patterns.iter().any(|pattern| {
            pattern == "installer_pkg_execution"
                || pattern == "open_executable_candidate"
                || pattern == "downloads_executable_reference"
        });

        if !installer_like {
            continue;
        }

        if is_benign_admin_tool_command(&process.command, &process.args)
            && !process.behavior.references_downloads_path
        {
            continue;
        }

        let high_signal = process.behavior.references_downloads_path
            || process.behavior.references_executable_candidate
            || process.behavior.has_shell_control_operator;

        if !high_signal {
            continue;
        }

        let severity = if process.behavior.references_downloads_path
            && process.behavior.references_executable_candidate
        {
            AlertSeverity::High
        } else {
            AlertSeverity::Medium
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "command_path_kind": process.command_path_kind,
            "matched_patterns": process.behavior.suspicious_command_patterns,
            "behavior": process.behavior,
            "parent_command": process.parent_command,
            "parent_args": process.parent_args,
            "parent_process_kind": process.parent_process_kind,
        });

        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_downloaded_installer_activity",
            severity,
            "installer_execution",
            "A process referenced executable installer-like content from Downloads",
            details,
        ));
    }

    detections
}

fn should_suppress_command_pattern_detection(process: &ProcessInfo) -> bool {
    let benign_dev = is_benign_developer_tool_command(&process.command, &process.args);
    let benign_admin = is_benign_admin_tool_command(&process.command, &process.args);

    (benign_dev || benign_admin)
        && !process.behavior.references_downloads_path
        && !process.behavior.references_persistence_path
        && !process.behavior.references_url
        && !process
            .behavior
            .suspicious_command_patterns
            .iter()
            .any(|pattern| {
                pattern == "network_tool_piped_to_shell"
                    || pattern == "launchctl_persistence_operation"
                    || pattern == "crontab_persistence_operation"
            })
}

fn should_suppress_interpreter_detection(process: &ProcessInfo) -> bool {
    is_benign_developer_tool_command(&process.command, &process.args)
        && !process.behavior.references_downloads_path
        && !process.behavior.references_persistence_path
        && !process.behavior.references_url
}

fn should_suppress_persistence_tool_detection(process: &ProcessInfo) -> bool {
    is_benign_admin_tool_command(&process.command, &process.args)
        && !process.behavior.references_downloads_path
        && !process.behavior.references_persistence_path
        && !process.behavior.references_url
}

fn is_benign_process_context(process: &ProcessInfo) -> bool {
    should_suppress_command_pattern_detection(process) && should_suppress_interpreter_detection(process)
}

fn chain_details(pid: i32, ctx: &DetectionContext) -> Value {
    if let Some(chain) = ctx.execution_graph.chain_for_pid(pid, 6) {
        execution_chain_json(&chain, &ctx.lineage, pid)
    } else {
        json!({
            "chain_root_pid": pid,
            "chain_root_command": "unknown",
            "attack_chain_length": 1,
            "chain_pids": [pid],
            "chain_commands": [],
            "related_paths": [],
            "lineage_depth": ctx.lineage.lineage_depth_for_pid(pid, 6),
            "browser_ancestor_present": ctx.lineage.has_browser_ancestor(pid, 6),
            "nearest_browser_ancestor": ctx.lineage.nearest_browser_ancestor_command(pid, 6),
            "descendant_count": ctx.lineage.descendant_count_for_pid(pid, 6),
        })
    }
}

fn execution_chain_json(chain: &ExecutionChain, lineage: &LineageSnapshot, pid: i32) -> Value {
    json!({
        "chain_root_pid": chain.chain_root_pid,
        "chain_root_command": chain.chain_root_command,
        "attack_chain_length": chain.attack_chain_length,
        "chain_pids": chain.pids,
        "chain_commands": chain.process_chain.iter().map(|p| p.command.clone()).collect::<Vec<String>>(),
        "related_paths": chain.related_paths,
        "lineage_depth": lineage.lineage_depth_for_pid(pid, 6),
        "browser_ancestor_present": lineage.has_browser_ancestor(pid, 6),
        "nearest_browser_ancestor": lineage.nearest_browser_ancestor_command(pid, 6),
        "descendant_count": lineage.descendant_count_for_pid(pid, 6),
    })
}

fn merge_chain_details(details: &mut Value, chain: Value) {
    if let (Some(details_map), Some(chain_map)) = (details.as_object_mut(), chain.as_object()) {
        for (key, value) in chain_map {
            details_map.insert(key.clone(), value.clone());
        }
    }
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
            "details": details,
        }),
    )
}

fn parent_dir_string(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string())
}