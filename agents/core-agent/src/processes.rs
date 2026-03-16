use crate::classify::{classify_path, classify_process_command};
use crate::models::{ProcessEvent, ProcessInfo, ProcessKey, TelemetryEvent};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone)]
struct RawProcessInfo {
    pid: i32,
    ppid: i32,
    command: String,
    args: String,
}

pub fn snapshot_processes() -> Result<HashMap<ProcessKey, ProcessInfo>> {
    let raw_processes = snapshot_raw_processes()?;
    let current = enrich_with_parent_context(raw_processes);
    Ok(current)
}

pub fn collect_new_process_events(
    previous: &HashMap<ProcessKey, ProcessInfo>,
    now: DateTime<Utc>,
) -> Result<(HashMap<ProcessKey, ProcessInfo>, Vec<ProcessEvent>)> {
    let current = snapshot_processes()?;
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
                    "parent_command_path_kind": process.parent_command_path_kind
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

fn snapshot_raw_processes() -> Result<HashMap<ProcessKey, RawProcessInfo>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid=,lstart=,command="])
        .output()
        .context("failed to execute ps command")?;

    if !output.status.success() {
        anyhow::bail!("ps command failed with status {:?}", output.status.code());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = HashMap::new();

    for line in stdout.lines() {
        if let Some((key, info)) = parse_ps_line(line) {
            if should_ignore_raw_process(&info) {
                continue;
            }
            processes.insert(key, info);
        }
    }

    Ok(processes)
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

            let process = ProcessInfo {
                pid: raw.pid,
                ppid: raw.ppid,
                command: raw.command.clone(),
                args: raw.args.clone(),
                process_kind: classify_process_command(&raw.command),
                command_path_kind: classify_path(&raw.command),
                parent_command: parent.map(|p| p.command.clone()),
                parent_args: parent.map(|p| p.args.clone()),
                parent_process_kind: parent.map(|p| classify_process_command(&p.command)),
                parent_command_path_kind: parent.map(|p| classify_path(&p.command)),
            };

            (key, process)
        })
        .collect()
}

fn parse_ps_line(line: &str) -> Option<(ProcessKey, RawProcessInfo)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }

    let pid = parts[0].parse::<i32>().ok()?;
    let ppid = parts[1].parse::<i32>().ok()?;

    let start_hint = parts[2..7].join(" ");
    let command_and_args = parts[7..].join(" ");
    if command_and_args.is_empty() {
        return None;
    }

    let mut split = command_and_args.splitn(2, ' ');
    let command = split.next().unwrap_or("").to_string();
    let args = split.next().unwrap_or("").to_string();

    let key = ProcessKey { pid, start_hint };

    let info = RawProcessInfo {
        pid,
        ppid,
        command,
        args,
    };

    Some((key, info))
}

fn should_ignore_raw_process(process: &RawProcessInfo) -> bool {
    let command = process.command.as_str();
    let args = process.args.as_str();
    let full = if args.is_empty() {
        command.to_string()
    } else {
        format!("{command} {args}")
    };

    if command == "ps" {
        return true;
    }

    if command.contains("/bin/ps") || command.contains("/usr/bin/ps") {
        return true;
    }

    if full.contains("ps -axo pid=,ppid=,lstart=,command=") {
        return true;
    }

    false
}