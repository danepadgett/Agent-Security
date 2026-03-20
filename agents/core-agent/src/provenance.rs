use crate::models::{FileEventRecord, ProcessInfo};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone)]
pub struct ArtifactProvenanceRecord {
    pub path: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub seen_count: u32,
    pub first_seen_in_downloads: bool,
    pub ever_executable: bool,
    pub ever_quarantined: bool,
    pub associated_pids: BTreeSet<i32>,
    pub referenced_urls: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ArtifactProvenanceSnapshot {
    pub records: HashMap<String, ArtifactProvenanceRecord>,
}

#[derive(Debug, Clone)]
pub struct ArtifactProvenanceCache {
    records: HashMap<String, ArtifactProvenanceRecord>,
    max_age_seconds: i64,
}

impl ArtifactProvenanceCache {
    pub fn new(max_age_seconds: i64) -> Self {
        Self {
            records: HashMap::new(),
            max_age_seconds,
        }
    }

    pub fn ingest_file_events(&mut self, events: &[FileEventRecord], now: DateTime<Utc>) {
        self.prune(now);

        for event in events {
            let entry = self
                .records
                .entry(event.path.clone())
                .or_insert_with(|| ArtifactProvenanceRecord {
                    path: event.path.clone(),
                    first_seen: event.timestamp,
                    last_seen: event.timestamp,
                    seen_count: 0,
                    first_seen_in_downloads: event.path.contains("/Downloads/"),
                    ever_executable: event.is_executable,
                    ever_quarantined: event.has_quarantine,
                    associated_pids: BTreeSet::new(),
                    referenced_urls: BTreeSet::new(),
                });

            entry.last_seen = event.timestamp;
            entry.seen_count += 1;
            entry.ever_executable |= event.is_executable;
            entry.ever_quarantined |= event.has_quarantine;
        }
    }

    pub fn ingest_processes(&mut self, processes: &[ProcessInfo], now: DateTime<Utc>) {
        self.prune(now);

        for process in processes {
            for path in &process.behavior.referenced_paths {
                let entry = self
                    .records
                    .entry(path.clone())
                    .or_insert_with(|| ArtifactProvenanceRecord {
                        path: path.clone(),
                        first_seen: now,
                        last_seen: now,
                        seen_count: 0,
                        first_seen_in_downloads: path.contains("/Downloads/"),
                        ever_executable: false,
                        ever_quarantined: false,
                        associated_pids: BTreeSet::new(),
                        referenced_urls: BTreeSet::new(),
                    });

                entry.last_seen = now;
                entry.seen_count += 1;
                entry.associated_pids.insert(process.pid);

                for url in &process.behavior.referenced_urls {
                    entry.referenced_urls.insert(url.clone());
                }
            }
        }
    }

    pub fn snapshot(&self) -> ArtifactProvenanceSnapshot {
        ArtifactProvenanceSnapshot {
            records: self.records.clone(),
        }
    }

    pub fn summary_json(&self) -> serde_json::Value {
        let items = self
            .records
            .values()
            .map(|record| {
                json!({
                    "path": record.path,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "seen_count": record.seen_count,
                    "first_seen_in_downloads": record.first_seen_in_downloads,
                    "ever_executable": record.ever_executable,
                    "ever_quarantined": record.ever_quarantined,
                    "associated_pids": record.associated_pids.iter().copied().collect::<Vec<i32>>(),
                    "referenced_urls": record.referenced_urls.iter().cloned().collect::<Vec<String>>(),
                })
            })
            .collect::<Vec<_>>();

        json!({
            "artifact_count": self.records.len(),
            "artifacts": items
        })
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.max_age_seconds);
        self.records.retain(|_, record| record.last_seen >= cutoff);
    }
}

impl ArtifactProvenanceSnapshot {
    pub fn get(&self, path: &str) -> Option<&ArtifactProvenanceRecord> {
        self.records.get(path)
    }
}