mod baseline;
mod classify;
mod command_features;
mod config;
mod detections;
mod execution_graph;
mod files;
mod guardrails;
mod incidents;
mod lineage;
mod logging;
mod models;
mod processes;
mod provenance;
mod replay;
mod response;
mod state;

use anyhow::Result;
use baseline::BaselineProfile;
use chrono::Utc;
use config::load_policy;
use detections::{evaluate_detections, DetectionContext};
use execution_graph::ExecutionGraphCache;
use files::{collect_file_events, scan_directories, tracked_directories};
use incidents::aggregate_incidents;
use lineage::ProcessLineageCache;
use logging::{append_event, append_response_audit};
use models::{FileEventRecord, TelemetryEvent};
use provenance::ArtifactProvenanceCache;
use response::handle_detection;
use state::{normalize_state_summary, AgentState};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::thread;
use std::time::Duration;

const ALERT_EMIT_COOLDOWN_SECONDS: i64 = 60;
const INCIDENT_EMIT_COOLDOWN_SECONDS: i64 = 120;
const INCIDENT_STATE_TTL_SECONDS: i64 = 3600;
const RESPONSE_STATE_TTL_SECONDS: i64 = 3600;
const LINEAGE_STATE_TTL_SECONDS: i64 = 1800;
const PROVENANCE_STATE_TTL_SECONDS: i64 = 3600;
const BASELINE_STATE_TTL_SECONDS: i64 = 7200;

fn main() -> Result<()> {
    if let Ok(replay_path) = env::var("CORE_AGENT_REPLAY_JSONL") {
        return replay::run_replay(&replay_path);
    }

    println!("Core Agent Starting...");

    let policy = load_policy()?;
    println!(
        "Response policy loaded: simulation_mode={}, enable_process_kill={}, enable_file_quarantine={}, kill_threshold={}, quarantine_threshold={}",
        policy.simulation_mode,
        policy.enable_process_kill,
        policy.enable_file_quarantine,
        policy.kill_threshold,
        policy.quarantine_threshold
    );

    let watch_dirs = tracked_directories();
    println!("Watching directories:");
    for dir in &watch_dirs {
        println!(" - {}", dir.display());
    }

    let mut previous_file_snapshot = scan_directories(&watch_dirs)?;
    let mut known_processes = processes::snapshot_processes()?;
    let mut recent_file_events: VecDeque<FileEventRecord> = VecDeque::new();
    let mut alert_last_seen: HashMap<String, chrono::DateTime<Utc>> = HashMap::new();
    let mut execution_graph = ExecutionGraphCache::new(300);
    let mut lineage_cache = ProcessLineageCache::new(LINEAGE_STATE_TTL_SECONDS);
    let mut provenance_cache = ArtifactProvenanceCache::new(PROVENANCE_STATE_TTL_SECONDS);
    let mut baseline_profile = BaselineProfile::new(BASELINE_STATE_TTL_SECONDS);
    let mut agent_state = AgentState::new();
    let mut startup_completed = false;
    let mut loop_counter: u64 = 0;

    loop {
        let now = Utc::now();
        loop_counter += 1;

        let (new_snapshot, file_events) =
            collect_file_events(&watch_dirs, &previous_file_snapshot, now)?;
        previous_file_snapshot = new_snapshot;

        for event in &file_events {
            println!("File event: kind={} path={}", event.kind, event.path.display());
            append_event(&event.telemetry_event)?;
            recent_file_events.push_back(FileEventRecord::from(event));
        }

        trim_recent_file_events(&mut recent_file_events, 300);
        trim_alert_cache(&mut alert_last_seen, 600, now);
        agent_state.prune(now, INCIDENT_STATE_TTL_SECONDS, RESPONSE_STATE_TTL_SECONDS);

        let (new_process_snapshot, process_events) =
            processes::collect_new_process_events(&known_processes, now)?;
        known_processes = new_process_snapshot;

        for event in &process_events {
            println!(
                "New process detected: pid={} command={} args={} kind={} parent_kind={}",
                event.process.pid,
                event.process.command,
                event.process.args,
                event.process.process_kind,
                event.process.parent_process_kind.as_deref().unwrap_or("unknown")
            );
            append_event(&event.telemetry_event)?;
        }

        let recent_processes = process_events
            .iter()
            .map(|event| event.process.clone())
            .collect::<Vec<_>>();

        let current_processes = known_processes.values().cloned().collect::<Vec<_>>();
        let current_file_window = recent_file_events.iter().cloned().collect::<Vec<_>>();

        execution_graph.ingest_processes(&recent_processes, &current_file_window, now);
        lineage_cache.ingest_processes(&current_processes, now);
        provenance_cache.ingest_file_events(&current_file_window, now);
        provenance_cache.ingest_processes(&recent_processes, now);
        baseline_profile.ingest_processes(&current_processes, now);

        if startup_completed {
            let detection_context = DetectionContext {
                recent_file_events: current_file_window.clone(),
                recent_processes: recent_processes.clone(),
                current_processes: current_processes.clone(),
                lineage: lineage_cache.snapshot(),
                provenance: provenance_cache.snapshot(),
                baseline: baseline_profile.snapshot(),
                execution_graph: execution_graph.snapshot(),
                now,
            };

            let detection_events = evaluate_detections(&detection_context);
            for detection in &detection_events {
                if should_emit_alert(
                    detection,
                    &mut alert_last_seen,
                    ALERT_EMIT_COOLDOWN_SECONDS,
                ) {
                    println!("ALERT: {}", detection.event_type);
                    append_event(detection)?;
                }
            }

            let incident_events = aggregate_incidents(&detection_events, now);
            for incident in incident_events {
                let (should_emit_incident, record) =
                    agent_state.should_emit_incident(&incident, INCIDENT_EMIT_COOLDOWN_SECONDS);

                if should_emit_incident {
                    println!(
                        "INCIDENT: {} key={} seen_count={} score={}",
                        incident.event_type,
                        record.incident_key,
                        record.seen_count,
                        record.last_score
                    );
                    append_event(&incident)?;

                    let response_events = handle_detection(&incident, &policy, &mut agent_state)?;
                    for response_event in response_events {
                        println!("RESPONSE: {}", response_event.event_type);
                        append_event(&response_event)?;
                        append_response_audit(&response_event)?;
                    }
                } else {
                    println!(
                        "INCIDENT SUPPRESSED: key={} seen_count={} score={}",
                        record.incident_key,
                        record.seen_count,
                        record.last_score
                    );
                }
            }

            if loop_counter % 30 == 0 {
                let state_summary = agent_state.snapshot_summary();
                let normalized = normalize_state_summary(&state_summary);

                let summary_event = TelemetryEvent::new(
                    now,
                    "agent_state_snapshot",
                    "core-agent/state",
                    serde_json::json!({
                        "state_summary": state_summary,
                        "normalized_summary": normalized,
                        "provenance_summary": provenance_cache.summary_json(),
                        "baseline_summary": baseline_profile.summary_json()
                    }),
                );
                append_event(&summary_event)?;
            }
        } else {
            println!("Startup baseline established. Alerting enabled on next loop.");
            startup_completed = true;
        }

        thread::sleep(Duration::from_secs(1));
    }
}

fn trim_recent_file_events(queue: &mut VecDeque<FileEventRecord>, seconds_to_keep: i64) {
    let cutoff = Utc::now() - chrono::Duration::seconds(seconds_to_keep);

    while let Some(front) = queue.front() {
        if front.timestamp < cutoff {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn should_emit_alert(
    event: &TelemetryEvent,
    cache: &mut HashMap<String, chrono::DateTime<Utc>>,
    cooldown_seconds: i64,
) -> bool {
    let fingerprint = detections::alert_fingerprint(event);
    let now = event.timestamp;

    if let Some(last_seen) = cache.get(&fingerprint) {
        let age = now.signed_duration_since(*last_seen).num_seconds();
        if age < cooldown_seconds {
            return false;
        }
    }

    cache.insert(fingerprint, now);
    true
}

fn trim_alert_cache(
    cache: &mut HashMap<String, chrono::DateTime<Utc>>,
    max_age_seconds: i64,
    now: chrono::DateTime<Utc>,
) {
    cache.retain(|_, timestamp| {
        now.signed_duration_since(*timestamp).num_seconds() <= max_age_seconds
    });
}