use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn run_replay(jsonl_path: &str) -> Result<()> {
    let file = File::open(jsonl_path)
        .with_context(|| format!("failed to open replay file {}", jsonl_path))?;
    let reader = BufReader::new(file);

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0usize;

    for line in reader.lines() {
        let line = line.with_context(|| "failed to read line from replay file")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let value: Value = serde_json::from_str(trimmed)
            .with_context(|| "failed to parse JSONL replay event")?;

        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        *counts.entry(event_type).or_insert(0) += 1;
        total += 1;
    }

    println!("Replay summary for {}", jsonl_path);
    println!("Total events: {}", total);
    for (event_type, count) in counts {
        println!("  {} -> {}", event_type, count);
    }

    Ok(())
}