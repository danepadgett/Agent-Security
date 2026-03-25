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
    /// Number of signals attributed to each PID — used for repeat-offender scoring.
    pid_signal_counts: HashMap<i32, usize>,
    /// MITRE ATT&CK technique IDs referenced by any signal in this incident.
    mitre_techniques: BTreeSet<String>,
    /// Earliest and latest event timestamps — used for time-window clustering.
    first_event_ts: Option<DateTime<Utc>>,
    last_event_ts: Option<DateTime<Utc>>,
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
                pid_signal_counts: HashMap::new(),
                mitre_techniques: BTreeSet::new(),
                first_event_ts: None,
                last_event_ts: None,
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

        // Track event timestamps for time-window clustering
        let ts = detection.timestamp;
        entry.first_event_ts = Some(entry.first_event_ts.map_or(ts, |prev| prev.min(ts)));
        entry.last_event_ts = Some(entry.last_event_ts.map_or(ts, |prev| prev.max(ts)));

        // Track MITRE techniques mentioned in this detection
        for technique in extract_mitre_techniques(detection) {
            entry.mitre_techniques.insert(technique);
        }

        if let Some(path) = extract_primary_path(detection) {
            entry.related_paths.insert(path);
        }

        for path in extract_related_paths(detection) {
            entry.related_paths.insert(path);
        }

        if let Some(pid) = extract_pid(detection) {
            entry.involved_pids.insert(pid);
            *entry.pid_signal_counts.entry(pid).or_insert(0) += 1;
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
    let has_downloader_url_execution = acc
        .signal_set
        .contains("alert_downloader_url_execution");
    let has_browser_ancestor_downloader_chain = acc
        .signal_set
        .contains("alert_browser_ancestor_downloader_chain");
    let has_persistence = acc.signal_set.contains("alert_persistence_artifact_touched");
    let has_persistence_tooling = acc.signal_set.contains("alert_persistence_tooling_activity");
    let has_suspicious_persistence_chain = acc
        .signal_set
        .contains("alert_suspicious_persistence_chain");
    let has_downloaded_installer = acc
        .signal_set
        .contains("alert_downloaded_installer_activity");

    // New signals from this session
    let has_lolbin = acc.signal_set.contains("alert_lolbin_execution");
    let has_curl_pipe_bash = acc.signal_set.contains("alert_curl_pipe_bash");
    let has_command_injection = acc.signal_set.contains("alert_command_injection_pattern");
    let has_keychain_access = acc.signal_set.contains("alert_keychain_access_attempt");
    let has_browser_cred_access = acc.signal_set.contains("alert_browser_credential_access");
    let has_ssh_key_access = acc.signal_set.contains("alert_ssh_key_access");
    let has_ransomware = acc.signal_set.contains("alert_ransomware_behavior_detected");
    let has_file_type_mismatch = acc.signal_set.contains("alert_file_type_mismatch");
    let has_masquerading = acc.signal_set.contains("alert_process_masquerading");
    let has_double_extension = acc.signal_set.contains("alert_double_extension_execution");

    // Final tranche signals
    let has_screen_capture = acc.signal_set.contains("alert_screen_capture_attempt")
        || acc.signal_set.contains("alert_suspicious_media_access");
    let has_data_staging = acc.signal_set.contains("alert_data_staging_detected")
        || acc.signal_set.contains("alert_suspicious_archive_creation");
    let has_ssh_lateral_movement = acc.signal_set.contains("alert_ssh_lateral_movement")
        || acc.signal_set.contains("alert_ssh_key_tampering");
    let has_browser_extension = acc.signal_set.contains("alert_browser_extension_installed");
    let has_exfiltration = acc.signal_set.contains("alert_suspected_exfiltration")
        || acc.signal_set.contains("alert_upload_command_detected");

    // New tranche — 6 additional detections
    let has_keylogging = acc.signal_set.contains("alert_keylogging_attempt");
    let has_boot_tamper = acc.signal_set.contains("alert_boot_security_tamper");
    let has_signed_proxy = acc.signal_set.contains("alert_signed_binary_proxy_execution");
    let has_security_tool_tamper = acc.signal_set.contains("alert_security_tool_tampering");
    let has_account_manipulation = acc.signal_set.contains("alert_account_manipulation");
    let has_plist_modification = acc.signal_set.contains("alert_plist_modification");

    let signal_count = acc.signal_set.len();

    // Time-window clustering: measure the span of all detection timestamps
    let event_span_seconds = match (acc.first_event_ts, acc.last_event_ts) {
        (Some(first), Some(last)) => last.signed_duration_since(first).num_seconds().max(0) as u64,
        _ => u64::MAX,
    };

    // Repeat offender: how many signals does the most-seen PID drive?
    let max_pid_signal_count = acc.pid_signal_counts.values().copied().max().unwrap_or(0);

    let breakdown = score_incident(
        has_download_exec,
        has_interpreter_downloads,
        has_shell_chain,
        has_exec_perm,
        has_command_pattern,
        has_interpreter_abuse,
        has_follow_on_binary,
        has_downloader_url_execution,
        has_browser_ancestor_downloader_chain,
        has_persistence,
        has_persistence_tooling,
        has_suspicious_persistence_chain,
        has_downloaded_installer,
        has_lolbin,
        has_curl_pipe_bash,
        has_command_injection,
        has_keychain_access,
        has_browser_cred_access,
        has_ssh_key_access,
        has_ransomware,
        has_file_type_mismatch,
        has_masquerading,
        has_double_extension,
        has_screen_capture,
        has_data_staging,
        has_ssh_lateral_movement,
        has_browser_extension,
        has_exfiltration,
        has_keylogging,
        has_boot_tamper,
        has_signed_proxy,
        has_security_tool_tamper,
        has_account_manipulation,
        has_plist_modification,
        signal_count,
        acc.attack_chain_length,
        event_span_seconds,
        max_pid_signal_count,
    )?;

    let related_paths: Vec<String> = acc.related_paths.iter().cloned().collect();
    let primary_path = related_paths.first().cloned();
    let path_kind = primary_path
        .as_deref()
        .map(classify_path)
        .unwrap_or_else(|| "unknown".to_string());

    let mitre_techniques: Vec<String> = acc.mitre_techniques.iter().cloned().collect();
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
                "event_span_seconds": event_span_seconds,
                "mitre_techniques": mitre_techniques,
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
    has_downloader_url_execution: bool,
    has_browser_ancestor_downloader_chain: bool,
    has_persistence: bool,
    has_persistence_tooling: bool,
    has_suspicious_persistence_chain: bool,
    has_downloaded_installer: bool,
    // New signals from later development
    has_lolbin: bool,
    has_curl_pipe_bash: bool,
    has_command_injection: bool,
    has_keychain_access: bool,
    has_browser_cred_access: bool,
    has_ssh_key_access: bool,
    has_ransomware: bool,
    has_file_type_mismatch: bool,
    has_masquerading: bool,
    has_double_extension: bool,
    has_screen_capture: bool,
    has_data_staging: bool,
    has_ssh_lateral_movement: bool,
    has_browser_extension: bool,
    has_exfiltration: bool,
    // New tranche — 6 additional detections
    has_keylogging: bool,
    has_boot_tamper: bool,
    has_signed_proxy: bool,
    has_security_tool_tamper: bool,
    has_account_manipulation: bool,
    has_plist_modification: bool,
    signal_count: usize,
    attack_chain_length: usize,
    // Span in seconds between earliest and latest detection timestamps in this incident.
    event_span_seconds: u64,
    // How many signals does the single most-active PID drive in this incident?
    max_pid_signal_count: usize,
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
                "Interpreter usage showed inline execution, script staging, persistence, or URL context"
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

    if has_downloader_url_execution {
        components.push(IncidentScoreComponent {
            name: "downloader_url_execution".to_string(),
            points: 18,
            reason: "Downloader-like execution referenced one or more URLs".to_string(),
        });
    }

    if has_browser_ancestor_downloader_chain {
        components.push(IncidentScoreComponent {
            name: "browser_ancestor_downloader_chain".to_string(),
            points: 14,
            reason: "Downloader-like execution originated from a browser ancestry chain".to_string(),
        });
    }

    if has_persistence {
        components.push(IncidentScoreComponent {
            name: "persistence_artifact_touch".to_string(),
            points: 15,
            reason: "A LaunchAgent, LaunchDaemon, or cron-style artifact was modified".to_string(),
        });
    }

    if has_persistence_tooling {
        components.push(IncidentScoreComponent {
            name: "persistence_tooling_activity".to_string(),
            points: 18,
            reason: "Persistence-oriented system tooling activity was observed".to_string(),
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

    // ── New signals ───────────────────────────────────────────────────────────

    if has_lolbin {
        components.push(IncidentScoreComponent {
            name: "lolbin_execution".to_string(),
            points: 16,
            reason: "LOLBin abuse detected — living-off-the-land execution evasion".to_string(),
        });
    }

    if has_curl_pipe_bash {
        components.push(IncidentScoreComponent {
            name: "curl_pipe_bash".to_string(),
            points: 22,
            reason: "Network tool output piped directly to shell — drive-by execution pattern".to_string(),
        });
    }

    if has_command_injection {
        components.push(IncidentScoreComponent {
            name: "command_injection_pattern".to_string(),
            points: 20,
            reason: "Command injection or reverse shell pattern detected".to_string(),
        });
    }

    if has_keychain_access {
        components.push(IncidentScoreComponent {
            name: "keychain_access_attempt".to_string(),
            points: 18,
            reason: "Keychain credential extraction attempt via security CLI".to_string(),
        });
    }

    if has_browser_cred_access {
        components.push(IncidentScoreComponent {
            name: "browser_credential_access".to_string(),
            points: 18,
            reason: "Non-browser process accessed browser credential store".to_string(),
        });
    }

    if has_ssh_key_access {
        components.push(IncidentScoreComponent {
            name: "ssh_key_access".to_string(),
            points: 16,
            reason: "Unexpected process accessed SSH private key or cloud credential file".to_string(),
        });
    }

    if has_ransomware {
        components.push(IncidentScoreComponent {
            name: "ransomware_behavior".to_string(),
            points: 30,
            reason: "Ransomware-characteristic behavioral pattern detected".to_string(),
        });
    }

    if has_file_type_mismatch {
        components.push(IncidentScoreComponent {
            name: "file_type_mismatch".to_string(),
            points: 14,
            reason: "File extension does not match actual content type — possible masquerading".to_string(),
        });
    }

    if has_masquerading {
        components.push(IncidentScoreComponent {
            name: "process_masquerading".to_string(),
            points: 16,
            reason: "Process name or path inconsistent with a legitimate system binary".to_string(),
        });
    }

    if has_double_extension {
        components.push(IncidentScoreComponent {
            name: "double_extension_execution".to_string(),
            points: 14,
            reason: "File with double extension designed to appear benign was executed".to_string(),
        });
    }

    if has_screen_capture {
        components.push(IncidentScoreComponent {
            name: "screen_capture_attempt".to_string(),
            points: 16,
            reason: "Screen or camera capture by a non-system, non-media process detected".to_string(),
        });
    }

    if has_data_staging {
        components.push(IncidentScoreComponent {
            name: "data_staging".to_string(),
            points: 18,
            reason: "Data collection or archive creation in a staging location detected".to_string(),
        });
    }

    if has_ssh_lateral_movement {
        components.push(IncidentScoreComponent {
            name: "ssh_lateral_movement".to_string(),
            points: 20,
            reason: "SSH-based lateral movement or key tampering activity detected".to_string(),
        });
    }

    if has_browser_extension {
        components.push(IncidentScoreComponent {
            name: "browser_extension_installed".to_string(),
            points: 14,
            reason: "New browser extension installed — potential persistence or credential theft vector".to_string(),
        });
    }

    if has_exfiltration {
        components.push(IncidentScoreComponent {
            name: "exfiltration_pattern".to_string(),
            points: 24,
            reason: "Data upload or exfiltration pattern detected in process arguments".to_string(),
        });
    }

    // ── New tranche signals ───────────────────────────────────────────────────

    if has_keylogging {
        components.push(IncidentScoreComponent {
            name: "keylogging_attempt".to_string(),
            points: 20,
            reason: "Process loaded a keyboard monitoring library or used AppleScript keystroke capture".to_string(),
        });
    }

    if has_boot_tamper {
        components.push(IncidentScoreComponent {
            name: "boot_security_tamper".to_string(),
            points: 30,
            reason: "SIP disable, nvram boot-security write, or kernel extension removal detected".to_string(),
        });
    }

    if has_signed_proxy {
        components.push(IncidentScoreComponent {
            name: "signed_binary_proxy_execution".to_string(),
            points: 16,
            reason: "Trusted system binary used to proxy execution of untrusted content".to_string(),
        });
    }

    if has_security_tool_tamper {
        components.push(IncidentScoreComponent {
            name: "security_tool_tampering".to_string(),
            points: 28,
            reason: "Gatekeeper disabled, security agent killed, or quarantine attribute stripped".to_string(),
        });
    }

    if has_account_manipulation {
        components.push(IncidentScoreComponent {
            name: "account_manipulation".to_string(),
            points: 20,
            reason: "Local user account creation or privilege modification detected".to_string(),
        });
    }

    if has_plist_modification {
        components.push(IncidentScoreComponent {
            name: "plist_modification".to_string(),
            points: 18,
            reason: "Persistence-domain plist modified via PlistBuddy, defaults, or plutil".to_string(),
        });
    }

    // ── Contextual bonuses ────────────────────────────────────────────────────

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

    // Time-window clustering: all signals within 30 seconds is a strong indicator
    // of an automated or scripted attack rather than user-initiated activity.
    if event_span_seconds <= 30 && signal_count >= 2 {
        components.push(IncidentScoreComponent {
            name: "tight_time_window".to_string(),
            points: 8,
            reason: format!(
                "All {} signals occurred within a {}-second window (automated/scripted attack pattern)",
                signal_count, event_span_seconds
            ),
        });
    }

    // Repeat offender: a single PID driving 3+ signals is strong evidence
    // of a malicious process rather than coincidental activity.
    if max_pid_signal_count >= 3 {
        let repeat_points = if max_pid_signal_count >= 5 { 12 } else { 8 };
        components.push(IncidentScoreComponent {
            name: "repeat_offender_pid".to_string(),
            points: repeat_points,
            reason: format!(
                "Single process drove {} signals — escalated suspicion for repeat offender",
                max_pid_signal_count
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
    let has_downloader = event_types.contains(&"alert_downloader_url_execution")
        || event_types.contains(&"alert_browser_ancestor_downloader_chain");
    let has_follow_on = event_types.contains(&"alert_suspicious_shell_chain")
        || event_types.contains(&"alert_interpreter_spawned_follow_on_binary");
    let has_persistence = event_types.contains(&"alert_persistence_artifact_touched")
        || event_types.contains(&"alert_suspicious_persistence_chain")
        || event_types.contains(&"alert_persistence_tooling_activity");
    let has_installer = event_types.contains(&"alert_downloaded_installer_activity");
    let has_credential_access = event_types.contains(&"alert_keychain_access_attempt")
        || event_types.contains(&"alert_browser_credential_access")
        || event_types.contains(&"alert_ssh_key_access");
    let has_lolbin_or_injection = event_types.contains(&"alert_lolbin_execution")
        || event_types.contains(&"alert_curl_pipe_bash")
        || event_types.contains(&"alert_command_injection_pattern");
    let has_ransomware = event_types.contains(&"alert_ransomware_behavior_detected");
    let has_ssh_lateral = event_types.contains(&"alert_ssh_lateral_movement")
        || event_types.contains(&"alert_ssh_key_tampering");
    let has_staging = event_types.contains(&"alert_data_staging_detected")
        || event_types.contains(&"alert_suspicious_archive_creation");
    let has_exfiltration = event_types.contains(&"alert_suspected_exfiltration")
        || event_types.contains(&"alert_upload_command_detected");
    let has_screen_capture = event_types.contains(&"alert_screen_capture_attempt")
        || event_types.contains(&"alert_suspicious_media_access");
    let has_browser_ext = event_types.contains(&"alert_browser_extension_installed");
    let has_keylogging = event_types.contains(&"alert_keylogging_attempt");
    let has_boot_tamper = event_types.contains(&"alert_boot_security_tamper");
    let has_signed_proxy = event_types.contains(&"alert_signed_binary_proxy_execution");
    let has_security_tool_tamper = event_types.contains(&"alert_security_tool_tampering");
    let has_account_manip = event_types.contains(&"alert_account_manipulation");
    let has_plist_mod = event_types.contains(&"alert_plist_modification");

    if has_ransomware {
        "ransomware_attack".to_string()
    } else if has_staging && has_exfiltration {
        "staging_and_exfil".to_string()
    } else if has_exfiltration && has_credential_access {
        "credential_theft_and_exfil".to_string()
    } else if has_exfiltration {
        "data_exfiltration".to_string()
    } else if has_ssh_lateral && has_credential_access {
        "lateral_movement_with_credential_theft".to_string()
    } else if has_ssh_lateral {
        "lateral_movement_chain".to_string()
    } else if has_staging {
        "data_staging_chain".to_string()
    } else if has_screen_capture && has_credential_access {
        "spyware_collection_chain".to_string()
    } else if has_screen_capture {
        "screen_capture_chain".to_string()
    } else if has_browser_ext && has_download_exec {
        "download_to_browser_persistence".to_string()
    } else if has_browser_ext {
        "browser_persistence_chain".to_string()
    } else if has_credential_access && has_download_exec {
        "download_to_credential_theft".to_string()
    } else if has_credential_access {
        "credential_theft".to_string()
    } else if has_lolbin_or_injection && has_persistence {
        "lolbin_to_persistence".to_string()
    } else if has_lolbin_or_injection {
        "lolbin_execution_chain".to_string()
    } else if has_download_exec && has_persistence {
        "download_to_persistence".to_string()
    } else if has_installer && has_persistence {
        "installer_to_persistence".to_string()
    } else if has_downloader && has_download_exec {
        "url_to_download_execution".to_string()
    } else if has_boot_tamper && has_security_tool_tamper {
        "full_defense_evasion_chain".to_string()
    } else if has_boot_tamper {
        "boot_security_tamper".to_string()
    } else if has_security_tool_tamper && has_persistence {
        "defense_evasion_to_persistence".to_string()
    } else if has_security_tool_tamper {
        "security_tool_disabled".to_string()
    } else if has_keylogging && has_credential_access {
        "keylogging_with_credential_theft".to_string()
    } else if has_keylogging {
        "keylogging_chain".to_string()
    } else if has_account_manip && has_persistence {
        "account_creation_to_persistence".to_string()
    } else if has_account_manip {
        "account_manipulation_chain".to_string()
    } else if has_plist_mod && has_download_exec {
        "download_to_plist_persistence".to_string()
    } else if has_plist_mod {
        "plist_persistence_chain".to_string()
    } else if has_signed_proxy && has_persistence {
        "signed_proxy_to_persistence".to_string()
    } else if has_signed_proxy {
        "signed_binary_proxy_chain".to_string()
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
        "alert_persistence_tooling_activity" => (
            "persistence tooling executed".to_string(),
            "Persistence-oriented system tooling activity was observed".to_string(),
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
        "alert_downloader_url_execution" => (
            "downloader referenced url".to_string(),
            "Downloader-like execution referenced one or more URLs".to_string(),
        ),
        "alert_browser_ancestor_downloader_chain" => (
            "browser-origin download chain".to_string(),
            "A browser ancestry chain led into downloader-like execution".to_string(),
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
        "alert_lolbin_execution" => (
            "LOLBin abuse".to_string(),
            "A living-off-the-land binary was used to evade detection or gain capabilities".to_string(),
        ),
        "alert_curl_pipe_bash" => (
            "network payload piped to shell".to_string(),
            "A network tool fetched content and piped it directly to a shell interpreter".to_string(),
        ),
        "alert_command_injection_pattern" => (
            "command injection / reverse shell".to_string(),
            "A command injection or reverse shell pattern was detected in process arguments".to_string(),
        ),
        "alert_keychain_access_attempt" => (
            "Keychain access attempt".to_string(),
            "The security CLI was used to extract credentials from the system Keychain".to_string(),
        ),
        "alert_browser_credential_access" => (
            "browser credential store accessed".to_string(),
            "A non-browser process accessed browser-stored login data or cookies".to_string(),
        ),
        "alert_ssh_key_access" => (
            "SSH / cloud credentials accessed".to_string(),
            "An unexpected process read an SSH private key or cloud credential file".to_string(),
        ),
        "alert_ransomware_behavior_detected" => (
            "ransomware behavior detected".to_string(),
            "Ransomware-characteristic behavioral signals were observed".to_string(),
        ),
        "alert_file_type_mismatch" => (
            "file type mismatch".to_string(),
            "A file's declared extension does not match its actual content type".to_string(),
        ),
        "alert_process_masquerading" => (
            "process masquerading".to_string(),
            "A process name or path is inconsistent with a legitimate system binary".to_string(),
        ),
        "alert_double_extension_execution" => (
            "double extension execution".to_string(),
            "A file with a double extension designed to appear benign was created or executed".to_string(),
        ),
        "alert_screen_capture_attempt" => (
            "screen capture attempt".to_string(),
            "screencapture or screenshot invoked by a non-system, non-media process".to_string(),
        ),
        "alert_suspicious_media_access" => (
            "suspicious media capture".to_string(),
            "Camera or media capture tool invoked by a suspicious or interpreter-origin process".to_string(),
        ),
        "alert_data_staging_detected" => (
            "data staging detected".to_string(),
            "Large number of files being copied to a staging location before potential exfiltration".to_string(),
        ),
        "alert_suspicious_archive_creation" => (
            "suspicious archive creation".to_string(),
            "Archive tool writing to a staging location or invoked by a suspicious process".to_string(),
        ),
        "alert_ssh_lateral_movement" => (
            "SSH lateral movement".to_string(),
            "SSH invoked with host-check bypass flags or by a suspicious-origin process".to_string(),
        ),
        "alert_ssh_key_tampering" => (
            "SSH key tampering".to_string(),
            "Authorized_keys file modified or SSH config read by an unexpected process".to_string(),
        ),
        "alert_browser_extension_installed" => (
            "browser extension installed".to_string(),
            "A new browser extension was installed or modified in a known extension directory".to_string(),
        ),
        "alert_upload_command_detected" => (
            "upload command detected".to_string(),
            "Network tool invoked with upload flags — potential data transmission".to_string(),
        ),
        "alert_suspected_exfiltration" => (
            "suspected data exfiltration".to_string(),
            "Upload command referencing user document or credential paths — likely exfiltration".to_string(),
        ),
        "alert_keylogging_attempt" => (
            "keylogging attempt".to_string(),
            "Process loaded a keyboard input monitoring library or used AppleScript keystroke capture".to_string(),
        ),
        "alert_boot_security_tamper" => (
            "boot security tampered".to_string(),
            "SIP disable, nvram boot-security write, or kernel extension removal detected".to_string(),
        ),
        "alert_signed_binary_proxy_execution" => (
            "signed binary proxy execution".to_string(),
            "Trusted Apple system binary used to proxy execution of untrusted content".to_string(),
        ),
        "alert_security_tool_tampering" => (
            "security tool disabled".to_string(),
            "Gatekeeper disabled, security agent killed, or quarantine attribute stripped in bulk".to_string(),
        ),
        "alert_account_manipulation" => (
            "account manipulation".to_string(),
            "Local user account created or modified, or privilege escalation via dscl/sysadminctl".to_string(),
        ),
        "alert_plist_modification" => (
            "persistence plist modified".to_string(),
            format!(
                "Persistence-domain plist modified via PlistBuddy, defaults, or plutil{}",
                format_path_suffix(path.as_deref())
            ),
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
        "alert_file_type_mismatch" => 12,
        "alert_double_extension_execution" => 14,
        "alert_file_became_executable" => 20,
        "alert_downloader_url_execution" => 25,
        "alert_browser_ancestor_downloader_chain" => 28,
        "alert_downloaded_file_executed" => 30,
        "alert_interpreter_launch_from_downloads" => 40,
        "alert_command_pattern_abuse" => 50,
        "alert_interpreter_abuse" => 55,
        "alert_lolbin_execution" => 57,
        "alert_curl_pipe_bash" => 58,
        "alert_command_injection_pattern" => 59,
        "alert_suspicious_shell_chain" => 70,
        "alert_interpreter_spawned_follow_on_binary" => 80,
        "alert_downloaded_installer_activity" => 85,
        "alert_process_masquerading" => 86,
        "alert_persistence_tooling_activity" => 88,
        "alert_keychain_access_attempt" => 89,
        "alert_browser_credential_access" => 89,
        "alert_ssh_key_access" => 89,
        "alert_persistence_artifact_touched" => 90,
        "alert_suspicious_persistence_chain" => 95,
        "alert_ransomware_behavior_detected" => 98,
        // Final tranche
        "alert_browser_extension_installed" => 72,
        "alert_system_recon_detected" => 74,
        "alert_network_recon_detected" => 75,
        "alert_filesystem_recon_detected" => 76,
        "alert_screen_capture_attempt" => 82,
        "alert_suspicious_media_access" => 83,
        "alert_suspicious_sudo_execution" => 87,
        "alert_privilege_escalation_attempt" => 88,
        "alert_data_staging_detected" => 91,
        "alert_suspicious_archive_creation" => 92,
        "alert_ssh_lateral_movement" => 93,
        "alert_ssh_key_tampering" => 94,
        "alert_indicator_removal_attempt" => 96,
        "alert_upload_command_detected" => 97,
        "alert_suspected_exfiltration" => 99,
        // New tranche 3
        "alert_signed_binary_proxy_execution" => 62,
        "alert_plist_modification" => 89,
        "alert_keylogging_attempt" => 90,
        "alert_account_manipulation" => 91,
        "alert_security_tool_tampering" => 96,
        "alert_boot_security_tamper" => 98,
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

/// Extract MITRE ATT&CK technique IDs from a detection event payload.
/// Handles both a single `"mitre_technique"` string and a
/// `"mitre_techniques"` array.
fn extract_mitre_techniques(event: &TelemetryEvent) -> Vec<String> {
    let Some(details) = event.payload.get("details") else {
        return Vec::new();
    };

    let mut techniques = Vec::new();

    if let Some(s) = details.get("mitre_technique").and_then(|v| v.as_str()) {
        if !s.is_empty() {
            techniques.push(s.to_string());
        }
    }

    if let Some(arr) = details.get("mitre_techniques").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if !s.is_empty() {
                    techniques.push(s.to_string());
                }
            }
        }
    }

    techniques
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Build a minimal synthetic detection event of the given type with optional details.
    fn make_detection(event_type: &str, pid: Option<i32>, mitre: Option<&str>) -> TelemetryEvent {
        let mut details = serde_json::json!({});
        if let Some(p) = pid {
            details["pid"] = serde_json::json!(p);
        }
        if let Some(m) = mitre {
            details["mitre_technique"] = serde_json::json!(m);
        }
        TelemetryEvent::new(
            Utc::now(),
            event_type,
            "test",
            serde_json::json!({ "details": details }),
        )
    }

    // ── extract_mitre_techniques ───────────────────────────────────────────────

    #[test]
    fn extract_mitre_techniques_finds_single_technique() {
        let event = make_detection("alert_keychain_access_attempt", Some(100), Some("T1555.001"));
        let techniques = extract_mitre_techniques(&event);
        assert!(techniques.contains(&"T1555.001".to_string()));
    }

    #[test]
    fn extract_mitre_techniques_finds_array() {
        let event = TelemetryEvent::new(
            Utc::now(),
            "alert_lolbin_execution",
            "test",
            serde_json::json!({
                "details": {
                    "mitre_techniques": ["T1059.004", "T1027"]
                }
            }),
        );
        let techniques = extract_mitre_techniques(&event);
        assert!(techniques.contains(&"T1059.004".to_string()));
        assert!(techniques.contains(&"T1027".to_string()));
    }

    #[test]
    fn extract_mitre_techniques_returns_empty_when_absent() {
        let event = make_detection("alert_burst_file_activity", None, None);
        let techniques = extract_mitre_techniques(&event);
        assert!(techniques.is_empty());
    }

    // ── aggregate_incidents: MITRE tagging ────────────────────────────────────

    /// Build a detection event with an explicit chain_root_pid so that multiple
    /// events group into the same incident bucket.
    fn make_detection_with_chain_root(
        event_type: &str,
        pid: i32,
        chain_root_pid: i32,
        mitre: &str,
    ) -> TelemetryEvent {
        TelemetryEvent::new(
            Utc::now(),
            event_type,
            "test",
            serde_json::json!({
                "details": {
                    "pid": pid,
                    "chain_root_pid": chain_root_pid,
                    "mitre_technique": mitre,
                }
            }),
        )
    }

    #[test]
    fn incidents_include_mitre_techniques_from_detections() {
        let now = Utc::now();
        // Both events share chain_root_pid=500, so they group together.
        // curl_pipe_bash(22) + command_injection(20) + keychain(18) = 60 >= 40 threshold.
        let d1 = make_detection_with_chain_root("alert_curl_pipe_bash", 501, 500, "T1059.004");
        let d2 = make_detection_with_chain_root("alert_keychain_access_attempt", 501, 500, "T1555.001");
        let d3 = make_detection_with_chain_root("alert_command_injection_pattern", 501, 500, "T1059.006");

        let incidents = aggregate_incidents(&[d1, d2, d3], now);
        assert!(!incidents.is_empty(), "should produce at least one incident");

        let incident = &incidents[0];
        let techniques = incident
            .payload
            .get("details")
            .and_then(|d| d.get("mitre_techniques"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let technique_strings: Vec<&str> = techniques
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        assert!(
            technique_strings.contains(&"T1059.004"),
            "incident should include T1059.004"
        );
        assert!(
            technique_strings.contains(&"T1555.001"),
            "incident should include T1555.001"
        );
    }

    // ── score_incident: time-window and repeat-offender bonuses ───────────────

    #[test]
    fn tight_time_window_bonus_fires_when_signals_within_30s() {
        // All false signals, only rely on time-window + signal count
        // Use two signals: curl_pipe_bash (22pts) + command_injection (20pts) = 42pts base
        // Then add tight_time_window bonus (8pts) = 50pts — should score
        let result = score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, true,  // has_curl_pipe_bash
            true,  false, false, false, false, false, false, false,  // has_command_injection
            false, false, false, false, false, // tranche 2 signals
            false, false, false, false, false, false, // tranche 3 signals
            2,  // signal_count
            1,  // attack_chain_length
            15, // event_span_seconds (within 30s window)
            1,  // max_pid_signal_count
        );
        assert!(result.is_some(), "should score above threshold");
        let breakdown = result.unwrap();
        assert!(
            breakdown.components.iter().any(|c| c.name == "tight_time_window"),
            "should include tight_time_window component"
        );
    }

    #[test]
    fn tight_time_window_bonus_does_not_fire_when_signals_spread_over_60s() {
        let result = score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, true, true, false, false, false, false, false, false, false,
            false, false, false, false, false,
            false, false, false, false, false, false,
            2, 1,
            61, // event_span_seconds (outside 30s window)
            1,
        );
        if let Some(breakdown) = result {
            assert!(
                !breakdown.components.iter().any(|c| c.name == "tight_time_window"),
                "tight_time_window should not fire when span > 30s"
            );
        }
    }

    #[test]
    fn repeat_offender_bonus_fires_for_pid_with_3_plus_signals() {
        let result = score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, true, true, false, false, false, false, false, false, false,
            false, false, false, false, false,
            false, false, false, false, false, false,
            2, 1,
            u64::MAX, // no time window bonus
            3, // max_pid_signal_count = 3
        );
        assert!(result.is_some(), "should score above threshold");
        let breakdown = result.unwrap();
        assert!(
            breakdown.components.iter().any(|c| c.name == "repeat_offender_pid"),
            "should include repeat_offender_pid component"
        );
    }

    #[test]
    fn repeat_offender_bonus_does_not_fire_for_pid_with_2_signals() {
        let result = score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, true, true, false, false, false, false, false, false, false,
            false, false, false, false, false,
            false, false, false, false, false, false,
            2, 1,
            u64::MAX,
            2, // only 2 signals from same pid — not enough
        );
        if let Some(breakdown) = result {
            assert!(
                !breakdown.components.iter().any(|c| c.name == "repeat_offender_pid"),
                "repeat_offender_pid should not fire for < 3 signals"
            );
        }
    }

    // ── New signal scoring ────────────────────────────────────────────────────

    #[test]
    fn ransomware_signal_scores_high() {
        let result = score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, false, false, false, false, false,
            true,  // has_ransomware — 30pts alone is below 40 threshold
            false, false, false,
            false, false, false, false, false,
            false, false, false, false, false, false,
            1, 1, u64::MAX, 1,
        );
        // 30pts alone is below 40 threshold — but pair with one other signal
        assert!(result.is_none(), "ransomware alone (30pts) is below 40pt threshold");
    }

    #[test]
    fn curl_pipe_bash_plus_command_injection_reaches_threshold() {
        let result = score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, true, true, false, false, false, false, false, false, false,
            false, false, false, false, false,
            false, false, false, false, false, false,
            2, 1, u64::MAX, 1,
        );
        assert!(result.is_some(), "curl_pipe_bash(22) + command_injection(20) = 42 >= 40 threshold");
    }

    // ── Final tranche signal scoring ──────────────────────────────────────────

    /// Helper: build the all-false argument list with only the named tranche positions set.
    /// Position indices (0-based) in the flattened score_incident call:
    ///  24=has_screen_capture, 25=has_data_staging, 26=has_ssh_lateral,
    ///  27=has_browser_extension, 28=has_exfiltration
    fn score_with_tranche(
        screen_capture: bool,
        data_staging: bool,
        ssh_lateral: bool,
        browser_ext: bool,
        exfiltration: bool,
        signal_count: usize,
    ) -> Option<crate::models::IncidentScoreBreakdown> {
        score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, false, false, false, false, false, false, false, false, false,
            screen_capture,
            data_staging,
            ssh_lateral,
            browser_ext,
            exfiltration,
            false, false, false, false, false, false, // new tranche 3
            signal_count, 1, u64::MAX, 1,
        )
    }

    #[test]
    fn exfiltration_signal_scores_above_threshold() {
        // exfiltration = 24pts; below 40pt threshold alone but paired with data_staging (18pts) = 42pts
        let result = score_with_tranche(false, true, false, false, true, 2);
        assert!(result.is_some(), "data_staging(18) + exfiltration(24) = 42 should exceed threshold");
        let breakdown = result.unwrap();
        assert!(breakdown.components.iter().any(|c| c.name == "exfiltration_pattern"));
        assert!(breakdown.components.iter().any(|c| c.name == "data_staging"));
    }

    #[test]
    fn ssh_lateral_signal_scores_with_credential_access() {
        // ssh_lateral = 20pts, keychain_access = 18pts → 38pts (below threshold alone)
        // add screen_capture = 16pts → 54pts ≥ 40
        let result = score_incident(
            false, false, false, false, false, false, false, false, false,
            false, false, false, false,
            false, false, false, true,  // has_keychain_access
            false, false, false, false, false, false,
            false, false, true,  // has_ssh_lateral
            false, false,
            false, false, false, false, false, false, // new tranche 3
            3, 1, u64::MAX, 1,
        );
        assert!(result.is_some(), "ssh_lateral + keychain_access + multi_signal should reach threshold");
        let breakdown = result.unwrap();
        assert!(breakdown.components.iter().any(|c| c.name == "ssh_lateral_movement"));
    }

    #[test]
    fn screen_capture_alone_does_not_reach_threshold() {
        // screen_capture = 16pts — below 40pt threshold alone
        let result = score_with_tranche(true, false, false, false, false, 1);
        assert!(result.is_none(), "screen_capture alone (16pts) is below 40pt threshold");
    }

    #[test]
    fn staging_plus_exfil_chain_label_is_staging_and_exfil() {
        use crate::models::IncidentTimelineStep;
        use chrono::Utc;
        let now = Utc::now();
        let make_step = |event_type: &str| IncidentTimelineStep {
            timestamp: now,
            event_type: event_type.to_string(),
            title: String::new(),
            description: String::new(),
            path: None,
            pid: None,
            parent_pid: None,
            score: None,
        };
        let timeline = vec![
            make_step("alert_suspicious_archive_creation"),
            make_step("alert_suspected_exfiltration"),
        ];
        let label = classify_attack_chain_label(&timeline);
        assert_eq!(label, "staging_and_exfil");
    }

    #[test]
    fn ssh_lateral_chain_label_is_lateral_movement_chain() {
        use crate::models::IncidentTimelineStep;
        use chrono::Utc;
        let now = Utc::now();
        let make_step = |event_type: &str| IncidentTimelineStep {
            timestamp: now,
            event_type: event_type.to_string(),
            title: String::new(),
            description: String::new(),
            path: None,
            pid: None,
            parent_pid: None,
            score: None,
        };
        let timeline = vec![make_step("alert_ssh_lateral_movement")];
        let label = classify_attack_chain_label(&timeline);
        assert_eq!(label, "lateral_movement_chain");
    }
}