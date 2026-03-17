use crate::classify::classify_path;
use crate::models::{
    AlertSeverity, IncidentNarrative, IncidentScoreBreakdown, IncidentScoreComponent,
    IncidentTimelineStep, TelemetryEvent,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::cmp::Ordering;
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
    detections: Vec<TelemetryEvent>,
}

pub fn aggregate_incidents(
    detections: &[TelemetryEvent],
    now: DateTime<Utc>,
) -> Vec<TelemetryEvent> {
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
                detections: Vec::new(),
            });

        if entry.signal_set.insert(detection.event_type.clone()) {
            entry.supporting_events.push(detection.event_type.clone());
        }

        entry.detections.push(detection.clone());

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

    let signal_count = acc.signal_set.len();
    let breakdown = score_incident(
        has_download_exec,
        has_interpreter_downloads,
        has_shell_chain,
        has_exec_perm,
        has_command_pattern,
        has_interpreter_abuse,
        has_follow_on_binary,
        has_persistence,
        has_suspicious_persistence_chain,
        has_downloaded_installer,
        signal_count,
        acc.attack_chain_length,
    )?;

    let related_paths: Vec<String> = acc.related_paths.iter().cloned().collect();
    let primary_path = related_paths.first().cloned();
    let path_kind = primary_path
        .as_deref()
        .map(classify_path)
        .unwrap_or_else(|| "unknown".to_string());

    let timeline = build_timeline(&acc.detections);
    let narrative = build_narrative(&timeline, &breakdown);

    Some(TelemetryEvent::new(
        now,
        "alert_behavioral_incident",
        "core-agent/incidents",
        json!({
            "severity": breakdown.severity,
            "score": breakdown.total_score,
            "category": "behavioral_incident",
            "reason": narrative.summary,
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
                "signal_count": signal_count,
                "attack_chain_length": acc.attack_chain_length,
                "confidence": breakdown.confidence,
                "score_breakdown": breakdown,
                "timeline": timeline,
                "narrative": narrative
            }
        }),
    ))
}

fn score_incident(
    has_download_exec: bool,
    has_interpreter_downloads: bool,
    has_shell_chain: bool,
    has_exec_perm: bool,
    has_command_pattern: bool,
    has_interpreter_abuse: bool,
    has_follow_on_binary: bool,
    has_persistence: bool,
    has_suspicious_persistence_chain: bool,
    has_downloaded_installer: bool,
    signal_count: usize,
    attack_chain_length: usize,
) -> Option<IncidentScoreBreakdown> {
    let mut components = Vec::new();

    if has_download_exec {
        components.push(IncidentScoreComponent {
            name: "downloaded_file_executed".to_string(),
            points: 20,
            reason: "Recently downloaded content appears to have been executed".to_string(),
        });
    }

    if has_interpreter_downloads {
        components.push(IncidentScoreComponent {
            name: "interpreter_launch_from_downloads".to_string(),
            points: 18,
            reason: "Interpreter execution referenced content from Downloads".to_string(),
        });
    }

    if has_shell_chain {
        components.push(IncidentScoreComponent {
            name: "shell_spawn_chain".to_string(),
            points: 18,
            reason: "A script or shell execution produced a follow-on child process".to_string(),
        });
    }

    if has_exec_perm {
        components.push(IncidentScoreComponent {
            name: "file_became_executable".to_string(),
            points: 10,
            reason: "A file gained executable permissions before or during execution".to_string(),
        });
    }

    if has_command_pattern {
        components.push(IncidentScoreComponent {
            name: "suspicious_command_pattern".to_string(),
            points: 20,
            reason: "Command line matched a high-signal suspicious execution pattern".to_string(),
        });
    }

    if has_interpreter_abuse {
        components.push(IncidentScoreComponent {
            name: "interpreter_abuse".to_string(),
            points: 16,
            reason:
                "Interpreter usage showed inline execution, script staging, or persistence references"
                    .to_string(),
        });
    }

    if has_follow_on_binary {
        components.push(IncidentScoreComponent {
            name: "follow_on_binary".to_string(),
            points: 16,
            reason: "Suspicious execution chain spawned a second-stage process".to_string(),
        });
    }

    if has_persistence {
        components.push(IncidentScoreComponent {
            name: "persistence_artifact_touch".to_string(),
            points: 15,
            reason: "A LaunchAgent or other persistence-related file was created or modified"
                .to_string(),
        });
    }

    if has_suspicious_persistence_chain {
        components.push(IncidentScoreComponent {
            name: "persistence_establishment_chain".to_string(),
            points: 24,
            reason: "Persistence behavior was linked to a suspicious execution chain".to_string(),
        });
    }

    if has_downloaded_installer {
        components.push(IncidentScoreComponent {
            name: "downloaded_installer_activity".to_string(),
            points: 14,
            reason:
                "Installer-like or launcher-like execution referenced executable content from Downloads"
                    .to_string(),
        });
    }

    if signal_count >= 3 {
        components.push(IncidentScoreComponent {
            name: "multi_signal_correlation".to_string(),
            points: 10,
            reason: format!(
                "Multiple independent detections correlated into one incident ({} signals)",
                signal_count
            ),
        });
    }

    if attack_chain_length >= 2 {
        let chain_points = if attack_chain_length >= 4 { 12 } else { 8 };
        components.push(IncidentScoreComponent {
            name: "attack_chain_depth".to_string(),
            points: chain_points,
            reason: format!(
                "Execution chain depth increased confidence (length = {})",
                attack_chain_length
            ),
        });
    }

    let raw_score: u16 = components.iter().map(|c| c.points as u16).sum();
    if raw_score < 40 {
        return None;
    }

    let total_score = raw_score.min(99) as u8;
    let severity = severity_from_score(total_score);
    let confidence = confidence_from_context(total_score, signal_count, attack_chain_length);

    Some(IncidentScoreBreakdown {
        total_score,
        confidence: confidence.to_string(),
        severity: severity.as_str().to_string(),
        attack_chain_length,
        signal_count,
        components,
    })
}

fn severity_from_score(score: u8) -> AlertSeverity {
    if score >= 95 {
        AlertSeverity::Critical
    } else if score >= 80 {
        AlertSeverity::High
    } else if score >= 55 {
        AlertSeverity::Medium
    } else {
        AlertSeverity::Low
    }
}

fn confidence_from_context(
    score: u8,
    signal_count: usize,
    attack_chain_length: usize,
) -> &'static str {
    if score >= 95 || (signal_count >= 4 && attack_chain_length >= 3) {
        "high"
    } else if score >= 75 || signal_count >= 3 {
        "medium"
    } else {
        "low"
    }
}

fn build_timeline(detections: &[TelemetryEvent]) -> Vec<IncidentTimelineStep> {
    let mut steps = detections
        .iter()
        .map(to_timeline_step)
        .collect::<Vec<IncidentTimelineStep>>();

    steps.sort_by(|a, b| match a.timestamp.cmp(&b.timestamp) {
        Ordering::Equal => timeline_priority(&a.event_type).cmp(&timeline_priority(&b.event_type)),
        other => other,
    });

    steps
}

fn build_narrative(
    timeline: &[IncidentTimelineStep],
    breakdown: &IncidentScoreBreakdown,
) -> IncidentNarrative {
    let attack_chain_label = classify_attack_chain_label(timeline);

    let step_titles = timeline
        .iter()
        .take(5)
        .map(|step| step.title.as_str())
        .collect::<Vec<&str>>();

    let summary = if step_titles.is_empty() {
        format!(
            "Correlated behavioral signals reached {} confidence",
            breakdown.confidence
        )
    } else {
        format!(
            "Correlated behavioral signals reached {} confidence: {}",
            breakdown.confidence,
            step_titles.join(" -> ")
        )
    };

    let short_story = if timeline.is_empty() {
        "No ordered timeline was available for this incident.".to_string()
    } else {
        timeline
            .iter()
            .take(5)
            .map(|step| step.description.clone())
            .collect::<Vec<String>>()
            .join(" Then ")
    };

    IncidentNarrative {
        summary,
        short_story,
        attack_chain_label,
    }
}

fn classify_attack_chain_label(timeline: &[IncidentTimelineStep]) -> String {
    let event_types = timeline
        .iter()
        .map(|step| step.event_type.as_str())
        .collect::<Vec<&str>>();

    let has_download_exec = event_types.contains(&"alert_downloaded_file_executed");
    let has_interpreter = event_types.contains(&"alert_interpreter_launch_from_downloads")
        || event_types.contains(&"alert_interpreter_abuse");
    let has_follow_on = event_types.contains(&"alert_suspicious_shell_chain")
        || event_types.contains(&"alert_interpreter_spawned_follow_on_binary");
    let has_persistence = event_types.contains(&"alert_persistence_artifact_touched")
        || event_types.contains(&"alert_suspicious_persistence_chain");
    let has_installer = event_types.contains(&"alert_downloaded_installer_activity");

    if has_download_exec && has_persistence {
        "download_to_persistence".to_string()
    } else if has_installer && has_persistence {
        "installer_to_persistence".to_string()
    } else if has_download_exec && has_interpreter && has_follow_on {
        "download_to_interpreter_to_child".to_string()
    } else if has_interpreter && has_persistence {
        "interpreter_to_persistence".to_string()
    } else if has_download_exec {
        "download_execution_chain".to_string()
    } else {
        "behavioral_chain".to_string()
    }
}

fn to_timeline_step(event: &TelemetryEvent) -> IncidentTimelineStep {
    let details = event.payload.get("details");

    let path = details
        .and_then(|d| {
            d.get("path")
                .and_then(|v| v.as_str())
                .or_else(|| d.get("matched_download_path").and_then(|v| v.as_str()))
                .or_else(|| d.get("persistence_path").and_then(|v| v.as_str()))
                .or_else(|| d.get("primary_path").and_then(|v| v.as_str()))
        })
        .map(|s| s.to_string());

    let pid = details
        .and_then(|d| d.get("pid").and_then(|v| v.as_i64()))
        .and_then(|v| i32::try_from(v).ok())
        .or_else(|| {
            details
                .and_then(|d| d.get("child_pid").and_then(|v| v.as_i64()))
                .and_then(|v| i32::try_from(v).ok())
        });

    let parent_pid = details
        .and_then(|d| d.get("parent_pid").and_then(|v| v.as_i64()))
        .and_then(|v| i32::try_from(v).ok());

    let score = event
        .payload
        .get("score")
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok());

    let (title, description) = match event.event_type.as_str() {
        "alert_downloaded_file_executed" => (
            "downloaded file executed".to_string(),
            format!(
                "Recently downloaded content was executed{}",
                format_path_suffix(path.as_deref())
            ),
        ),
        "alert_interpreter_launch_from_downloads" => (
            "interpreter launched downloaded content".to_string(),
            format!(
                "A script interpreter launched content from Downloads{}",
                format_path_suffix(path.as_deref())
            ),
        ),
        "alert_file_became_executable" => (
            "file became executable".to_string(),
            format!(
                "A file gained executable permissions{}",
                format_path_suffix(path.as_deref())
            ),
        ),
        "alert_quarantined_file_activity" => (
            "quarantined file activity".to_string(),
            format!(
                "A quarantined Downloads item was created or modified{}",
                format_path_suffix(path.as_deref())
            ),
        ),
        "alert_persistence_artifact_touched" => (
            "persistence artifact touched".to_string(),
            format!(
                "A persistence-related file was created or modified{}",
                format_path_suffix(path.as_deref())
            ),
        ),
        "alert_suspicious_shell_chain" => (
            "shell chain spawned child".to_string(),
            "A shell or script execution spawned a follow-on child process".to_string(),
        ),
        "alert_command_pattern_abuse" => (
            "suspicious command pattern".to_string(),
            "A high-signal suspicious command pattern was observed".to_string(),
        ),
        "alert_interpreter_abuse" => (
            "interpreter abuse observed".to_string(),
            "Interpreter execution showed high-signal abuse characteristics".to_string(),
        ),
        "alert_interpreter_spawned_follow_on_binary" => (
            "interpreter spawned follow-on binary".to_string(),
            "A suspicious interpreter process spawned a second-stage child process".to_string(),
        ),
        "alert_suspicious_persistence_chain" => (
            "suspicious chain touched persistence".to_string(),
            format!(
                "A suspicious execution chain appears to have established or modified persistence{}",
                format_path_suffix(path.as_deref())
            ),
        ),
        "alert_downloaded_installer_activity" => (
            "downloaded installer activity".to_string(),
            "Installer-like or launcher-like execution referenced executable content from Downloads"
                .to_string(),
        ),
        "alert_burst_file_activity" => (
            "burst file activity".to_string(),
            "Unusually high file activity occurred in a short time window".to_string(),
        ),
        other => (
            other.to_string(),
            "Behavioral detection contributed to the incident".to_string(),
        ),
    };

    IncidentTimelineStep {
        timestamp: event.timestamp,
        event_type: event.event_type.clone(),
        title,
        description,
        path,
        pid,
        parent_pid,
        score,
    }
}

fn format_path_suffix(path: Option<&str>) -> String {
    match path {
        Some(value) => format!(" at {}", value),
        None => String::new(),
    }
}

fn timeline_priority(event_type: &str) -> u8 {
    match event_type {
        "alert_quarantined_file_activity" => 10,
        "alert_file_became_executable" => 20,
        "alert_downloaded_file_executed" => 30,
        "alert_interpreter_launch_from_downloads" => 40,
        "alert_command_pattern_abuse" => 50,
        "alert_interpreter_abuse" => 60,
        "alert_suspicious_shell_chain" => 70,
        "alert_interpreter_spawned_follow_on_binary" => 80,
        "alert_downloaded_installer_activity" => 85,
        "alert_persistence_artifact_touched" => 90,
        "alert_suspicious_persistence_chain" => 95,
        _ => 100,
    }
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