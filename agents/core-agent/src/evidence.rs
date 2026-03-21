use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::path::Path;

const INCIDENT_DIR: &str = "runtime/incidents";

pub fn write_incident_evidence_pack(
    incident: &TelemetryEvent,
    response_events: &[TelemetryEvent],
) -> Result<String> {
    fs::create_dir_all(INCIDENT_DIR)
        .with_context(|| format!("failed to create {}", INCIDENT_DIR))?;

    let incident_key = incident
        .payload
        .get("incident_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown_incident".to_string());

    let score = incident
        .payload
        .get("score")
        .and_then(|v| v.as_u64());

    let severity = incident
        .payload
        .get("severity")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let details = incident
        .payload
        .get("details")
        .cloned()
        .unwrap_or(Value::Null);

    let primary_path = details
        .get("primary_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let matched_download_path = details
        .get("matched_download_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let persistence_path = details
        .get("persistence_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let involved_pids = details
        .get("involved_pids")
        .cloned()
        .unwrap_or_else(|| json!([]));

    let related_paths = details
        .get("related_paths")
        .cloned()
        .unwrap_or_else(|| json!([]));

    let timeline = details
        .get("timeline")
        .cloned()
        .unwrap_or_else(|| json!([]));

    let file_name = format!(
        "{}_{}_{}.json",
        incident.timestamp.timestamp(),
        sanitize_filename(&incident.event_type),
        sanitize_filename(&incident_key)
    );

    let output_path = Path::new(INCIDENT_DIR).join(file_name);

    let pack = json!({
        "schema_version": 1,
        "generated_at": Utc::now(),
        "incident": {
            "id": incident.id,
            "timestamp": incident.timestamp,
            "event_type": incident.event_type,
            "source": incident.source,
            "payload": incident.payload,
        },
        "summary": {
            "incident_key": incident_key,
            "score": score,
            "severity": severity,
            "primary_path": primary_path,
            "matched_download_path": matched_download_path,
            "persistence_path": persistence_path,
            "involved_pids": involved_pids,
            "related_paths": related_paths,
            "response_count": response_events.len(),
        },
        "timeline": timeline,
        "responses": response_events.iter().map(event_to_json).collect::<Vec<_>>(),
        "metadata": {
            "first_response_timestamp": first_response_timestamp(response_events),
            "last_response_timestamp": last_response_timestamp(response_events),
        }
    });

    let file = File::create(&output_path)
        .with_context(|| format!("failed to create incident evidence pack {}", output_path.display()))?;

    serde_json::to_writer_pretty(file, &pack)
        .with_context(|| format!("failed to write incident evidence pack {}", output_path.display()))?;

    Ok(output_path.to_string_lossy().to_string())
}

fn event_to_json(event: &TelemetryEvent) -> Value {
    json!({
        "id": event.id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "source": event.source,
        "payload": event.payload,
    })
}

fn first_response_timestamp(events: &[TelemetryEvent]) -> Option<DateTime<Utc>> {
    events.iter().map(|e| e.timestamp).min()
}

fn last_response_timestamp(events: &[TelemetryEvent]) -> Option<DateTime<Utc>> {
    events.iter().map(|e| e.timestamp).max()
}

fn sanitize_filename(value: &str) -> String {
    let mut out = String::with_capacity(value.len());

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }

    out.trim_matches('_').to_string()
}