use crate::models::TelemetryEvent;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone)]
pub struct IncidentRecord {
    pub incident_key: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub seen_count: u32,
    pub last_score: u8,
    pub confidence: Option<String>,
    pub supporting_events: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResponseActionRecord {
    pub incident_key: String,
    pub action_key: String,
    pub first_executed: DateTime<Utc>,
    pub last_executed: DateTime<Utc>,
    pub execution_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct AgentState {
    incidents: HashMap<String, IncidentRecord>,
    response_actions: HashMap<String, ResponseActionRecord>,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            incidents: HashMap::new(),
            response_actions: HashMap::new(),
        }
    }

    pub fn register_incident(&mut self, event: &TelemetryEvent) -> IncidentRecord {
        let key = incident_key(event);
        let now = event.timestamp;
        let score = alert_score(event);
        let confidence = incident_confidence(event);
        let supporting_events = incident_supporting_events(event);

        let entry = self
            .incidents
            .entry(key.clone())
            .or_insert_with(|| IncidentRecord {
                incident_key: key.clone(),
                first_seen: now,
                last_seen: now,
                seen_count: 0,
                last_score: score,
                confidence: confidence.clone(),
                supporting_events: supporting_events.clone(),
            });

        entry.last_seen = now;
        entry.seen_count += 1;
        entry.last_score = score;
        entry.confidence = confidence;
        if !supporting_events.is_empty() {
            entry.supporting_events = supporting_events;
        }

        entry.clone()
    }

    pub fn should_emit_incident(
        &mut self,
        event: &TelemetryEvent,
        cooldown_seconds: i64,
    ) -> (bool, IncidentRecord) {
        let record = self.register_incident(event);
        let age = record
            .last_seen
            .signed_duration_since(record.first_seen)
            .num_seconds();

        let should_emit = record.seen_count == 1 || age >= cooldown_seconds;
        (should_emit, record)
    }

    pub fn should_allow_response_action(
        &mut self,
        incident_key: &str,
        action_key: &str,
        now: DateTime<Utc>,
        cooldown_seconds: i64,
    ) -> bool {
        let composite = format!("{incident_key}::{action_key}");

        if let Some(existing) = self.response_actions.get(&composite) {
            let age = now
                .signed_duration_since(existing.last_executed)
                .num_seconds();
            if age < cooldown_seconds {
                return false;
            }
        }

        true
    }

    pub fn record_response_action(
        &mut self,
        incident_key: &str,
        action_key: &str,
        now: DateTime<Utc>,
    ) {
        let composite = format!("{incident_key}::{action_key}");

        let entry = self
            .response_actions
            .entry(composite.clone())
            .or_insert_with(|| ResponseActionRecord {
                incident_key: incident_key.to_string(),
                action_key: action_key.to_string(),
                first_executed: now,
                last_executed: now,
                execution_count: 0,
            });

        entry.last_executed = now;
        entry.execution_count += 1;
    }

    pub fn prune(&mut self, now: DateTime<Utc>, incident_ttl_seconds: i64, action_ttl_seconds: i64) {
        let incident_cutoff = now - Duration::seconds(incident_ttl_seconds);
        self.incidents
            .retain(|_, record| record.last_seen >= incident_cutoff);

        let action_cutoff = now - Duration::seconds(action_ttl_seconds);
        self.response_actions
            .retain(|_, record| record.last_executed >= action_cutoff);
    }

    pub fn snapshot_summary(&self) -> serde_json::Value {
        let incident_count = self.incidents.len();
        let action_count = self.response_actions.len();

        let hottest_incidents = self
            .incidents
            .values()
            .map(|record| {
                json!({
                    "incident_key": record.incident_key,
                    "seen_count": record.seen_count,
                    "last_score": record.last_score,
                    "confidence": record.confidence,
                    "supporting_events": record.supporting_events,
                })
            })
            .collect::<Vec<_>>();

        let action_summary = self
            .response_actions
            .values()
            .map(|record| {
                json!({
                    "incident_key": record.incident_key,
                    "action_key": record.action_key,
                    "execution_count": record.execution_count,
                    "last_executed": record.last_executed,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "incident_count": incident_count,
            "response_action_count": action_count,
            "incidents": hottest_incidents,
            "response_actions": action_summary
        })
    }
}

pub fn incident_key(event: &TelemetryEvent) -> String {
    let details = event.payload.get("details");

    if let Some(grouping_key) = details
        .and_then(|d| d.get("grouping_key"))
        .and_then(|v| v.as_str())
    {
        return grouping_key.to_string();
    }

    if let Some(chain_root_pid) = details
        .and_then(|d| d.get("chain_root_pid"))
        .and_then(|v| v.as_i64())
    {
        return format!("chain_root_pid:{chain_root_pid}");
    }

    if let Some(primary_path) = details
        .and_then(|d| d.get("primary_path"))
        .and_then(|v| v.as_str())
    {
        return format!("primary_path:{primary_path}");
    }

    format!("event_type:{}:{}", event.event_type, event.id)
}

fn alert_score(event: &TelemetryEvent) -> u8 {
    event.payload
        .get("score")
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0)
}

fn incident_confidence(event: &TelemetryEvent) -> Option<String> {
    event.payload
        .get("details")
        .and_then(|d| d.get("confidence"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn incident_supporting_events(event: &TelemetryEvent) -> Vec<String> {
    event.payload
        .get("details")
        .and_then(|d| d.get("supporting_events"))
        .and_then(|v| v.as_array())
        .map(|items| {
            let mut out = BTreeSet::new();
            for item in items {
                if let Some(text) = item.as_str() {
                    out.insert(text.to_string());
                }
            }
            out.into_iter().collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

pub fn response_action_key(event_type: &str, target_identifier: &str) -> String {
    format!("{event_type}:{target_identifier}")
}

pub fn normalize_state_summary(value: &serde_json::Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    if let Some(count) = value.get("incident_count").and_then(|v| v.as_u64()) {
        out.insert("incident_count".to_string(), count.to_string());
    }

    if let Some(count) = value.get("response_action_count").and_then(|v| v.as_u64()) {
        out.insert("response_action_count".to_string(), count.to_string());
    }

    out
}