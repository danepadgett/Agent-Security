use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub payload: Value,
}

impl TelemetryEvent {
    pub fn new(timestamp: DateTime<Utc>, event_type: &str, source: &str, payload: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp,
            event_type: event_type.to_string(),
            source: source.to_string(),
            payload,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Low => "low",
            AlertSeverity::Medium => "medium",
            AlertSeverity::High => "high",
            AlertSeverity::Critical => "critical",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            AlertSeverity::Low => 25,
            AlertSeverity::Medium => 50,
            AlertSeverity::High => 75,
            AlertSeverity::Critical => 95,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentScoreComponent {
    pub name: String,
    pub points: u8,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentScoreBreakdown {
    pub total_score: u8,
    pub confidence: String,
    pub severity: String,
    pub attack_chain_length: usize,
    pub signal_count: usize,
    pub components: Vec<IncidentScoreComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentTimelineStep {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub title: String,
    pub description: String,
    pub path: Option<String>,
    pub pid: Option<i32>,
    pub parent_pid: Option<i32>,
    pub score: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentNarrative {
    pub summary: String,
    pub short_story: String,
    pub attack_chain_label: String,
}

#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub modified_unix_seconds: i64,
    pub size_bytes: u64,
    pub is_executable: bool,
    pub has_quarantine: bool,
    pub quarantine_value: Option<String>,
}

pub type FileSnapshotMap = HashMap<PathBuf, FileSnapshot>;

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub kind: String,
    pub path: PathBuf,
    pub timestamp: DateTime<Utc>,
    pub telemetry_event: TelemetryEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventRecord {
    pub kind: String,
    pub path: String,
    pub timestamp: DateTime<Utc>,
    pub size_bytes: u64,
    pub is_executable: bool,
    pub has_quarantine: bool,
    pub quarantine_value: Option<String>,
}

impl From<&FileEvent> for FileEventRecord {
    fn from(value: &FileEvent) -> Self {
        let payload = &value.telemetry_event.payload;

        Self {
            kind: value.kind.clone(),
            path: value.path.to_string_lossy().to_string(),
            timestamp: value.timestamp,
            size_bytes: payload
                .get("size_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            is_executable: payload
                .get("is_executable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            has_quarantine: payload
                .get("has_quarantine")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            quarantine_value: payload
                .get("quarantine_value")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ProcessKey {
    pub pid: i32,
    pub start_hint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessBehaviorFeatures {
    pub has_pipe: bool,
    pub has_shell_control_operator: bool,
    pub has_inline_code_execution: bool,
    pub uses_network_download_tool: bool,
    pub references_downloads_path: bool,
    pub references_persistence_path: bool,
    pub references_script_file: bool,
    pub references_executable_candidate: bool,
    pub references_url: bool,
    pub downloader_family: Option<String>,
    pub suspicious_command_patterns: Vec<String>,
    pub referenced_paths: Vec<String>,
    pub referenced_urls: Vec<String>,
    pub token_count: usize,
    pub network_indicator_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub command: String,
    pub args: String,
    pub process_kind: String,
    pub command_path_kind: String,
    pub parent_command: Option<String>,
    pub parent_args: Option<String>,
    pub parent_process_kind: Option<String>,
    pub parent_command_path_kind: Option<String>,
    pub behavior: ProcessBehaviorFeatures,
}

impl ProcessInfo {
    pub fn placeholder(pid: i32) -> Self {
        Self {
            pid,
            ppid: 0,
            command: format!("unknown:{pid}"),
            args: String::new(),
            process_kind: "unknown".to_string(),
            command_path_kind: "unknown".to_string(),
            parent_command: None,
            parent_args: None,
            parent_process_kind: None,
            parent_command_path_kind: None,
            behavior: ProcessBehaviorFeatures::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub process: ProcessInfo,
    pub telemetry_event: TelemetryEvent,
}