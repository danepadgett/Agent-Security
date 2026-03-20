use crate::classify::{is_benign_admin_tool_command, is_benign_developer_tool_command};
use crate::models::ProcessInfo;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BaselineRecord {
    pub fingerprint: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub seen_count: u32,
    pub command: String,
    pub process_kind: String,
}

#[derive(Debug, Clone, Default)]
pub struct BaselineSnapshot {
    pub records: HashMap<String, BaselineRecord>,
}

#[derive(Debug, Clone)]
pub struct BaselineProfile {
    records: HashMap<String, BaselineRecord>,
    max_age_seconds: i64,
}

impl BaselineProfile {
    pub fn new(max_age_seconds: i64) -> Self {
        Self {
            records: HashMap::new(),
            max_age_seconds,
        }
    }

    pub fn ingest_processes(&mut self, processes: &[ProcessInfo], now: DateTime<Utc>) {
        self.prune(now);

        for process in processes {
            let fingerprint = process_fingerprint(process);

            let entry = self
                .records
                .entry(fingerprint.clone())
                .or_insert_with(|| BaselineRecord {
                    fingerprint,
                    first_seen: now,
                    last_seen: now,
                    seen_count: 0,
                    command: process.command.clone(),
                    process_kind: process.process_kind.clone(),
                });

            entry.last_seen = now;
            entry.seen_count += 1;
            entry.command = process.command.clone();
            entry.process_kind = process.process_kind.clone();
        }
    }

    pub fn snapshot(&self) -> BaselineSnapshot {
        BaselineSnapshot {
            records: self.records.clone(),
        }
    }

    pub fn summary_json(&self) -> serde_json::Value {
        let items = self
            .records
            .values()
            .map(|record| {
                json!({
                    "fingerprint": record.fingerprint,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "seen_count": record.seen_count,
                    "command": record.command,
                    "process_kind": record.process_kind,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "baseline_count": self.records.len(),
            "entries": items
        })
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.max_age_seconds);
        self.records.retain(|_, record| record.last_seen >= cutoff);
    }
}

impl BaselineSnapshot {
    pub fn seen_count_for(&self, process: &ProcessInfo) -> u32 {
        let fingerprint = process_fingerprint(process);
        self.records
            .get(&fingerprint)
            .map(|record| record.seen_count)
            .unwrap_or(0)
    }

    pub fn is_baselined_benign(&self, process: &ProcessInfo) -> bool {
        let seen_count = self.seen_count_for(process);

        let benign_tool = is_benign_developer_tool_command(&process.command, &process.args)
            || is_benign_admin_tool_command(&process.command, &process.args);

        benign_tool
            && seen_count >= 5
            && !process.behavior.references_downloads_path
            && !process.behavior.references_persistence_path
            && !process.behavior.references_url
    }
}

pub fn process_fingerprint(process: &ProcessInfo) -> String {
    let command_name = Path::new(&process.command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&process.command)
        .to_ascii_lowercase();

    let args = process.args.to_ascii_lowercase();

    let compact_args = if args.len() > 80 {
        args[..80].to_string()
    } else {
        args
    };

    format!("{}|{}|{}", command_name, process.process_kind, compact_args)
}