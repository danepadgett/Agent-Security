use crate::models::TelemetryEvent;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn run_replay(jsonl_path: &str) -> Result<()> {
    let events = load_events(jsonl_path)?;
    let summary = build_summary(&events);

    print_replay_summary(jsonl_path, &events, &summary);

    if let Ok(expected_path) = std::env::var("CORE_AGENT_REPLAY_EXPECTED_JSON") {
        let expectations = load_expectations(&expected_path)?;
        validate_expectations(&summary, &expectations)
            .with_context(|| format!("replay expectation validation failed for {}", expected_path))?;
        println!("Replay expectations satisfied: {}", expected_path);
    }

    Ok(())
}

fn load_events(jsonl_path: &str) -> Result<Vec<TelemetryEvent>> {
    let file = File::open(jsonl_path)
        .with_context(|| format!("failed to open replay file {}", jsonl_path))?;
    let reader = BufReader::new(file);

    let mut events: Vec<TelemetryEvent> = Vec::new();

    for line in reader.lines() {
        let line = line.with_context(|| "failed to read line from replay file")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: TelemetryEvent = serde_json::from_str(trimmed)
            .or_else(|_| {
                let value: Value = serde_json::from_str(trimmed)
                    .with_context(|| "failed to parse JSONL replay event as generic JSON")?;
                value_to_event(value)
            })
            .with_context(|| "failed to parse replay event")?;

        events.push(event);
    }

    Ok(events)
}

fn value_to_event(value: Value) -> Result<TelemetryEvent> {
    let event: TelemetryEvent = serde_json::from_value(value)
        .with_context(|| "failed to convert generic JSON into TelemetryEvent")?;
    Ok(event)
}

#[derive(Debug, Clone, Default)]
struct ReplaySummary {
    total_events: usize,
    total_alerts: usize,
    total_incidents: usize,
    total_responses: usize,
    event_type_counts: BTreeMap<String, usize>,
    alert_counts: BTreeMap<String, usize>,
    response_counts: BTreeMap<String, usize>,
    response_outcomes: BTreeMap<String, usize>,
}

fn build_summary(events: &[TelemetryEvent]) -> ReplaySummary {
    let mut summary = ReplaySummary {
        total_events: events.len(),
        ..Default::default()
    };

    for event in events {
        *summary
            .event_type_counts
            .entry(event.event_type.clone())
            .or_insert(0) += 1;

        if event.event_type.starts_with("alert_") {
            summary.total_alerts += 1;
            *summary
                .alert_counts
                .entry(event.event_type.clone())
                .or_insert(0) += 1;
        }

        if event.event_type == "alert_behavioral_incident" {
            summary.total_incidents += 1;
        }

        if event.event_type.starts_with("response_") {
            summary.total_responses += 1;
            *summary
                .response_counts
                .entry(event.event_type.clone())
                .or_insert(0) += 1;

            if let Some(outcome) = event
                .payload
                .get("outcome")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
            {
                *summary.response_outcomes.entry(outcome).or_insert(0) += 1;
            }
        }
    }

    summary
}

fn print_replay_summary(path: &str, events: &[TelemetryEvent], summary: &ReplaySummary) {
    println!();
    println!("Replay summary for {}", path);
    println!("==================================================");
    println!("Total events: {}", summary.total_events);
    println!("Total alerts: {}", summary.total_alerts);
    println!("Total incidents: {}", summary.total_incidents);
    println!("Total responses: {}", summary.total_responses);
    println!();

    println!("Top event types:");
    print_sorted_counts(&summary.event_type_counts, 15);

    if !summary.alert_counts.is_empty() {
        println!();
        println!("Alert breakdown:");
        print_sorted_counts(&summary.alert_counts, 15);
    }

    if !summary.response_counts.is_empty() {
        println!();
        println!("Response breakdown:");
        print_sorted_counts(&summary.response_counts, 15);
    }

    if !summary.response_outcomes.is_empty() {
        println!();
        println!("Response outcomes:");
        print_sorted_counts(&summary.response_outcomes, 15);
    }

    let high_signal_events = collect_high_signal_events(events);
    if !high_signal_events.is_empty() {
        println!();
        println!("High-signal timeline:");
        for event in high_signal_events {
            println!(
                "  [{}] {} :: {}",
                event.timestamp.to_rfc3339(),
                event.event_type,
                summarize_event(event)
            );
        }
    }

    println!("==================================================");
    println!();
}

fn print_sorted_counts(counts: &BTreeMap<String, usize>, limit: usize) {
    let mut pairs: Vec<(&String, &usize)> = counts.iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    for (key, count) in pairs.into_iter().take(limit) {
        println!("  {} -> {}", key, count);
    }
}

fn collect_high_signal_events(events: &[TelemetryEvent]) -> Vec<&TelemetryEvent> {
    events
        .iter()
        .filter(|event| {
            event.event_type.starts_with("alert_")
                || event.event_type.starts_with("response_")
                || event.event_type == "agent_state_snapshot"
        })
        .collect()
}

fn summarize_event(event: &TelemetryEvent) -> String {
    if event.event_type.starts_with("response_") {
        let action = event
            .payload
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_action");

        let outcome = event
            .payload
            .get("outcome")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_outcome");

        let pid = event
            .payload
            .get("pid")
            .and_then(|v| v.as_i64())
            .map(|v| format!("pid={}", v));

        let path = event
            .payload
            .get("path")
            .or_else(|| event.payload.get("old_path"))
            .or_else(|| event.payload.get("new_path"))
            .and_then(|v| v.as_str())
            .map(|v| format!("path={}", v));

        let reason = event
            .payload
            .get("reason")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());

        return [
            Some(format!("action={}", action)),
            Some(format!("outcome={}", outcome)),
            pid,
            path,
            reason,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" • ");
    }

    if event.event_type.starts_with("alert_") {
        let title = event
            .payload
            .get("title")
            .or_else(|| event.payload.get("reason"))
            .and_then(|v| v.as_str())
            .unwrap_or("alert");

        let score = event
            .payload
            .get("score")
            .and_then(|v| v.as_u64())
            .map(|v| format!("score={}", v));

        let path = event
            .payload
            .get("path")
            .and_then(|v| v.as_str())
            .map(|v| format!("path={}", v));

        return [Some(title.to_string()), score, path]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" • ");
    }

    if event.event_type == "agent_state_snapshot" {
        return "periodic state snapshot".to_string();
    }

    event.event_type.clone()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReplayExpectations {
    min_total_events: Option<usize>,
    min_total_alerts: Option<usize>,
    min_total_incidents: Option<usize>,
    min_total_responses: Option<usize>,
    required_event_types: Option<BTreeMap<String, usize>>,
    required_alert_types: Option<BTreeMap<String, usize>>,
    required_response_types: Option<BTreeMap<String, usize>>,
    required_response_outcomes: Option<BTreeMap<String, usize>>,
}

fn load_expectations(path: &str) -> Result<ReplayExpectations> {
    let file = File::open(path)
        .with_context(|| format!("failed to open replay expectation file {}", path))?;
    let reader = BufReader::new(file);

    let expectations: ReplayExpectations = serde_json::from_reader(reader)
        .with_context(|| format!("failed to parse replay expectations from {}", path))?;

    Ok(expectations)
}

fn validate_expectations(summary: &ReplaySummary, expected: &ReplayExpectations) -> Result<()> {
    if let Some(min) = expected.min_total_events {
        if summary.total_events < min {
            bail!(
                "expected at least {} total events, observed {}",
                min,
                summary.total_events
            );
        }
    }

    if let Some(min) = expected.min_total_alerts {
        if summary.total_alerts < min {
            bail!(
                "expected at least {} total alerts, observed {}",
                min,
                summary.total_alerts
            );
        }
    }

    if let Some(min) = expected.min_total_incidents {
        if summary.total_incidents < min {
            bail!(
                "expected at least {} total incidents, observed {}",
                min,
                summary.total_incidents
            );
        }
    }

    if let Some(min) = expected.min_total_responses {
        if summary.total_responses < min {
            bail!(
                "expected at least {} total responses, observed {}",
                min,
                summary.total_responses
            );
        }
    }

    validate_required_counts(
        "event type",
        &summary.event_type_counts,
        expected.required_event_types.as_ref(),
    )?;
    validate_required_counts(
        "alert type",
        &summary.alert_counts,
        expected.required_alert_types.as_ref(),
    )?;
    validate_required_counts(
        "response type",
        &summary.response_counts,
        expected.required_response_types.as_ref(),
    )?;
    validate_required_counts(
        "response outcome",
        &summary.response_outcomes,
        expected.required_response_outcomes.as_ref(),
    )?;

    Ok(())
}

fn validate_required_counts(
    label: &str,
    observed: &BTreeMap<String, usize>,
    required: Option<&BTreeMap<String, usize>>,
) -> Result<()> {
    let Some(required) = required else {
        return Ok(());
    };

    for (key, min_expected) in required {
        let actual = observed.get(key).copied().unwrap_or(0);
        if actual < *min_expected {
            bail!(
                "expected {} '{}' at least {} time(s), observed {}",
                label,
                key,
                min_expected,
                actual
            );
        }
    }

    Ok(())
}