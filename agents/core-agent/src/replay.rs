use crate::models::TelemetryEvent;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn run_replay(jsonl_path: &str) -> Result<()> {
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

    print_replay_summary(jsonl_path, &events);
    Ok(())
}

fn value_to_event(value: Value) -> Result<TelemetryEvent> {
    let event: TelemetryEvent = serde_json::from_value(value)
        .with_context(|| "failed to convert generic JSON into TelemetryEvent")?;
    Ok(event)
}

fn print_replay_summary(path: &str, events: &[TelemetryEvent]) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut alert_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut response_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut response_outcomes: BTreeMap<String, usize> = BTreeMap::new();

    let mut total_alerts = 0usize;
    let mut total_incidents = 0usize;
    let mut total_responses = 0usize;

    for event in events {
        *counts.entry(event.event_type.clone()).or_insert(0) += 1;

        if event.event_type.starts_with("alert_") {
            total_alerts += 1;
            *alert_counts.entry(event.event_type.clone()).or_insert(0) += 1;
        }

        if event.event_type == "alert_behavioral_incident" {
            total_incidents += 1;
        }

        if event.event_type.starts_with("response_") {
            total_responses += 1;
            *response_counts.entry(event.event_type.clone()).or_insert(0) += 1;

            if let Some(outcome) = event
                .payload
                .get("outcome")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
            {
                *response_outcomes.entry(outcome).or_insert(0) += 1;
            }
        }
    }

    println!();
    println!("Replay summary for {}", path);
    println!("==================================================");
    println!("Total events: {}", events.len());
    println!("Total alerts: {}", total_alerts);
    println!("Total incidents: {}", total_incidents);
    println!("Total responses: {}", total_responses);
    println!();

    println!("Top event types:");
    print_sorted_counts(&counts, 15);

    if !alert_counts.is_empty() {
        println!();
        println!("Alert breakdown:");
        print_sorted_counts(&alert_counts, 15);
    }

    if !response_counts.is_empty() {
        println!();
        println!("Response breakdown:");
        print_sorted_counts(&response_counts, 15);
    }

    if !response_outcomes.is_empty() {
        println!();
        println!("Response outcomes:");
        print_sorted_counts(&response_outcomes, 15);
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

        return [Some(format!("action={}", action)), Some(format!("outcome={}", outcome)), pid, path, reason]
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