use crate::classify::{classify_path, classify_process_command};
use crate::command_features::extract_features;
use crate::models::{ProcessEvent, ProcessInfo, ProcessKey, TelemetryEvent};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::HashMap;
use sysinfo::System;

#[derive(Debug, Clone)]
struct RawProcessInfo {
    pid: i32,
    ppid: i32,
    command: String,
    args: String,
}

pub fn snapshot_processes(sys: &mut System) -> Result<HashMap<ProcessKey, ProcessInfo>> {
    let raw_processes = snapshot_raw_processes(sys);
    let current = enrich_with_parent_context(raw_processes);
    Ok(current)
}

pub fn collect_new_process_events(
    sys: &mut System,
    previous: &HashMap<ProcessKey, ProcessInfo>,
    now: DateTime<Utc>,
) -> Result<(HashMap<ProcessKey, ProcessInfo>, Vec<ProcessEvent>)> {
    let current = snapshot_processes(sys)?;
    let mut events = Vec::new();

    for (key, process) in &current {
        if !previous.contains_key(key) {
            let telemetry_event = TelemetryEvent::new(
                now,
                "process_started",
                "core-agent/processes",
                json!({
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "command": process.command,
                    "args": process.args,
                    "process_kind": process.process_kind,
                    "command_path_kind": process.command_path_kind,
                    "parent_command": process.parent_command,
                    "parent_args": process.parent_args,
                    "parent_process_kind": process.parent_process_kind,
                    "parent_command_path_kind": process.parent_command_path_kind,
                    "behavior": process.behavior,
                }),
            );

            events.push(ProcessEvent {
                process: process.clone(),
                telemetry_event,
            });
        }
    }

    Ok((current, events))
}

/// Enumerate running processes using sysinfo (kernel API, no subprocess spawn).
/// Uses process start_time as uniqueness hint to prevent PID-reuse false positives.
/// Accepts a long-lived `System` object to avoid the allocation overhead of
/// creating a new one every tick — caller owns the `System` across iterations.
fn snapshot_raw_processes(sys: &mut System) -> HashMap<ProcessKey, RawProcessInfo> {
    sys.refresh_processes();

    let mut processes = HashMap::new();

    for (pid, process) in sys.processes() {
        let pid_i32 = pid.as_u32() as i32;
        let ppid_i32 = process.parent().map(|p| p.as_u32() as i32).unwrap_or(0);

        // Use exe path when available for accurate path classification;
        // fall back to process name (basename only).
        let command = process
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| process.name().to_string());

        // argv[0] is the program name/path — skip it; rest are the arguments.
        let args: String = process
            .cmd()
            .iter()
            .skip(1)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" ");

        // start_time is seconds since Unix epoch — stable across enumeration ticks.
        let start_hint = process.start_time().to_string();

        let raw = RawProcessInfo { pid: pid_i32, ppid: ppid_i32, command, args };
        let key = ProcessKey { pid: pid_i32, start_hint };
        processes.insert(key, raw);
    }

    processes
}

fn enrich_with_parent_context(
    raw_processes: HashMap<ProcessKey, RawProcessInfo>,
) -> HashMap<ProcessKey, ProcessInfo> {
    let pid_lookup: HashMap<i32, RawProcessInfo> =
        raw_processes.values().map(|p| (p.pid, p.clone())).collect();

    raw_processes
        .into_iter()
        .map(|(key, raw)| {
            let parent = pid_lookup.get(&raw.ppid);

            let normalized_command = normalize_command_token(&raw.command);
            let normalized_parent_command =
                parent.map(|p| normalize_command_token(&p.command));

            let process = ProcessInfo {
                pid: raw.pid,
                ppid: raw.ppid,
                command: normalized_command.clone(),
                args: raw.args.clone(),
                process_kind: classify_process_command(&normalized_command),
                command_path_kind: classify_path(&normalized_command),
                parent_command: normalized_parent_command.clone(),
                parent_args: parent.map(|p| p.args.clone()),
                parent_process_kind: normalized_parent_command
                    .as_ref()
                    .map(|cmd| classify_process_command(cmd)),
                parent_command_path_kind: normalized_parent_command
                    .as_ref()
                    .map(|cmd| classify_path(cmd)),
                behavior: extract_features(&normalized_command, &raw.args),
            };

            (key, process)
        })
        .collect()
}

fn normalize_command_token(command: &str) -> String {
    let trimmed = command.trim();

    if trimmed.is_empty() {
        return String::new();
    }

    let without_parens = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed)
        .trim();

    if without_parens.is_empty() {
        return trimmed.to_string();
    }

    without_parens.to_string()
}