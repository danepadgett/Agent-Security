mod baseline;
mod classify;
mod command_features;
mod command_patterns;
mod config;
mod config_integrity;
mod perf;
mod detections;
mod evidence;
mod execution_graph;
mod files;
mod guardrails;
mod incidents;
mod lineage;
mod logging;
mod models;
mod network;
mod persistence_monitor;
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
use evidence::write_incident_evidence_pack;
use execution_graph::ExecutionGraphCache;
use files::{collect_file_events, scan_directories, tracked_directories};
use incidents::aggregate_incidents;
use lineage::ProcessLineageCache;
use logging::{append_event, append_response_audit};
use models::{FileEventRecord, TelemetryEvent};
use network::NetworkMonitor;
use persistence_monitor::PersistenceMonitor;
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

    let args: Vec<String> = env::args().collect();
    let perf_report_mode = args.contains(&"--perf-report".to_string());

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

    // ── Performance tracker ────────────────────────────────────────────────────
    // Throttle kicks in if any subsystem exceeds 50ms in a single loop iteration.
    let mut perf = perf::PerfTracker::new(50_000, 50);
    perf.capture_rss_baseline();

    // ── Self-protection: startup integrity check ───────────────────────────────
    let (mut integrity_state, startup_tamper_events) = config_integrity::startup_check();
    for tamper in &startup_tamper_events {
        let event = models::TelemetryEvent::new(
            Utc::now(),
            tamper.kind.as_event_type(),
            "core-agent/self-protection",
            serde_json::json!({
                "severity": tamper.kind.severity(),
                "category": "defense_evasion",
                "reason": &tamper.detail,
                "details": { "detail": &tamper.detail },
            }),
        );
        println!("TAMPER DETECTED at startup: {} — {}", tamper.kind.as_event_type(), tamper.detail);
        let _ = logging::append_event(&event);
    }

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
    let mut persistence_monitor = PersistenceMonitor::new();
    let mut network_monitor = NetworkMonitor::new();
    let mut startup_completed = false;
    let mut loop_counter: u64 = 0;

    loop {
        let now = Utc::now();
        loop_counter += 1;

        // ── File monitor ───────────────────────────────────────────────────────
        let t_file = std::time::Instant::now();
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
        perf.record_raw("file_monitor", t_file.elapsed());

        // ── Process monitor ────────────────────────────────────────────────────
        let t_proc = std::time::Instant::now();
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
        perf.record_raw("process_monitor", t_proc.elapsed());

        if startup_completed {
            // ── Persistence monitor (crontab + loginwindow hooks) ──────────────
            let t_persist = std::time::Instant::now();
            let persistence_events = persistence_monitor.check_and_update(now);
            for event in &persistence_events {
                println!("PERSISTENCE: {}", event.event_type);
                append_event(event)?;
            }
            perf.record_raw("persistence_monitor", t_persist.elapsed());

            // ── Network telemetry ──────────────────────────────────────────────
            let t_net = std::time::Instant::now();
            // Build a pid → process_kind map for connection classification
            let process_kind_map: HashMap<i32, String> = current_processes
                .iter()
                .map(|p| (p.pid, p.process_kind.clone()))
                .collect();

            let network_events = network_monitor.snapshot_and_detect(&process_kind_map, now);
            for event in &network_events {
                if event.event_type.starts_with("alert_") {
                    println!("NETWORK ALERT: {}", event.event_type);
                }
                append_event(event)?;
            }
            perf.record_raw("network_monitor", t_net.elapsed());

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

            let t_detect = std::time::Instant::now();
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
            perf.record_raw("detection_eval", t_detect.elapsed());

            let t_incident = std::time::Instant::now();
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
                    for response_event in &response_events {
                        println!("RESPONSE: {}", response_event.event_type);
                        append_event(response_event)?;
                        append_response_audit(response_event)?;
                    }

                    match write_incident_evidence_pack(&incident, &response_events) {
                        Ok(pack_path) => {
                            let evidence_event = TelemetryEvent::response(
                                now,
                                "response_evidence_pack_created",
                                serde_json::json!({
                                    "action": "evidence_pack_write",
                                    "target_type": "incident",
                                    "response_mode": "system",
                                    "outcome": "executed",
                                    "incident_key": record.incident_key,
                                    "path": pack_path,
                                    "reason": "Structured incident evidence pack written to disk"
                                }),
                            );
                            append_event(&evidence_event)?;
                            append_response_audit(&evidence_event)?;
                        }
                        Err(err) => {
                            let evidence_error_event = TelemetryEvent::response(
                                now,
                                "response_evidence_pack_failed",
                                serde_json::json!({
                                    "action": "evidence_pack_write",
                                    "target_type": "incident",
                                    "response_mode": "system",
                                    "outcome": "failed",
                                    "incident_key": record.incident_key,
                                    "reason": format!("Failed to write incident evidence pack: {}", err)
                                }),
                            );
                            append_event(&evidence_error_event)?;
                            append_response_audit(&evidence_error_event)?;
                        }
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
            perf.record_raw("incident_correlation", t_incident.elapsed());

            // ── Periodic integrity check ───────────────────────────────────────
            if loop_counter % 240 == 0 {
                // ~60 seconds at 250ms cadence
                let tamper_events = config_integrity::periodic_check(&mut integrity_state);
                for tamper in &tamper_events {
                    let event = models::TelemetryEvent::new(
                        now,
                        tamper.kind.as_event_type(),
                        "core-agent/self-protection",
                        serde_json::json!({
                            "severity": tamper.kind.severity(),
                            "category": "defense_evasion",
                            "reason": &tamper.detail,
                            "details": { "detail": &tamper.detail },
                        }),
                    );
                    println!("TAMPER: {} — {}", tamper.kind.as_event_type(), tamper.detail);
                    let _ = logging::append_event(&event);
                }
                // Snapshot current log manifest once per minute
                config_integrity::update_log_manifest(&mut integrity_state);
            }

            if loop_counter % 30 == 0 {
                let state_summary = agent_state.snapshot_summary();
                let normalized = normalize_state_summary(&state_summary);

                let summary_event = TelemetryEvent::state(
                    now,
                    "agent_state_snapshot",
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

        // ── Perf flush and throttle ────────────────────────────────────────────
        if perf.tick() {
            perf.flush(&now);
            if perf_report_mode {
                perf.print_report();
                // In --perf-report mode, run for one flush window then exit.
                return Ok(());
            }
        }

        let base_sleep = Duration::from_millis(250);
        let throttle_extra = Duration::from_millis(perf.throttle_extra_sleep_ms());
        thread::sleep(base_sleep + throttle_extra);
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