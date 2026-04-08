/// Filesystem Anomaly Detection — Tranche 2 Upgrade 4
///
/// Detects mass file creation with ransomware extensions, ransom note creation,
/// and mass file modification patterns that indicate ransomware or destructive malware.
///
/// MITRE coverage:
///   T1486 — Data Encrypted for Impact (ransomware)
///   T1485 — Data Destruction (mass file modification)
///
/// Note: FSEvents via the notify crate does not provide rename events on macOS,
/// so ransomware detection is adapted to track file_created events with ransomware
/// extensions rather than tracking actual file renames.
use crate::models::{AlertSeverity, FileEventRecord, TelemetryEvent};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::HashMap;

/// Known ransomware encrypted file extensions.
/// These extensions are placed on encrypted files to signal the ransom demand.
static RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted", ".enc", ".locked", ".crypto", ".crypt",
    ".cryp1", ".crypt1", ".zepto", ".cerber", ".wnry",
    ".wncry", ".wcry", ".locky", ".sage", ".odin",
    ".thor", ".aesir", ".shit", ".dharma", ".wallet",
    ".zzzzz", ".aaa", ".abc", ".xyz", ".evil",
    ".ransom", ".pay2me", ".payrec",
];

/// Known ransom note filenames.
static RANSOM_NOTE_NAMES: &[&str] = &[
    "readme.txt", "read_me.txt", "read_this.txt", "how_to_decrypt",
    "decryption_instructions", "your_files_are_encrypted",
    "pay_ransom", "files_encrypted", "_readme.txt", "!readme!",
    "howdecrypt", "how_recover", "ransomed.html", "restore_files",
    "about_files", "help_decrypt", "recover_files",
];

pub struct FilesystemAnomalyDetector {
    /// Window in seconds to track file events for burst/ransomware detection.
    window_seconds: i64,
    /// Count of files with ransomware extensions created in the current window,
    /// keyed by directory prefix (to group by location).
    ransomware_extension_counts: HashMap<String, Vec<DateTime<Utc>>>,
    /// Tracks recently modified file count per directory for mass-rw pattern.
    modification_counts: HashMap<String, Vec<DateTime<Utc>>>,
    /// Whether we've already fired the ransomware alert (avoid storm).
    ransomware_alert_fired: bool,
}

impl FilesystemAnomalyDetector {
    pub fn new() -> Self {
        Self {
            window_seconds: 30,
            ransomware_extension_counts: HashMap::new(),
            modification_counts: HashMap::new(),
            ransomware_alert_fired: false,
        }
    }

    /// Process new file events and return any anomaly alerts.
    pub fn process_events(
        &mut self,
        events: &[FileEventRecord],
        now: DateTime<Utc>,
    ) -> Vec<TelemetryEvent> {
        let mut alerts = Vec::new();
        let cutoff = now - Duration::seconds(self.window_seconds);

        for event in events {
            if event.timestamp < cutoff {
                continue;
            }

            let path_lower = event.path.to_ascii_lowercase();
            let basename = event.path
                .rsplit('/')
                .next()
                .unwrap_or(&event.path)
                .to_ascii_lowercase();

            // Track ransomware extension wave (file_created with ransomware extension)
            if event.kind == "file_created" || event.kind == "file_modified" {
                let has_ransomware_ext = RANSOMWARE_EXTENSIONS
                    .iter()
                    .any(|ext| path_lower.ends_with(ext));

                if has_ransomware_ext && !self.ransomware_alert_fired {
                    // Group by parent directory
                    let parent_dir = event.path.rsplit('/').nth(1)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| event.path.clone());

                    let timestamps = self.ransomware_extension_counts
                        .entry(parent_dir.clone())
                        .or_insert_with(Vec::new);
                    timestamps.retain(|t| now.signed_duration_since(*t).num_seconds() <= self.window_seconds);
                    timestamps.push(event.timestamp);

                    // Fire at 5+ files with ransomware extensions in window
                    if timestamps.len() >= 5 {
                        self.ransomware_alert_fired = true;
                        alerts.push(build_ransomware_wave_alert(
                            now,
                            &event.path,
                            timestamps.len(),
                            self.window_seconds,
                        ));
                        timestamps.clear();
                    }
                }
            }

            // Ransom note detection — high-signal standalone alert
            if event.kind == "file_created" {
                let is_ransom_note = RANSOM_NOTE_NAMES
                    .iter()
                    .any(|name| basename.contains(name));

                if is_ransom_note {
                    alerts.push(build_ransom_note_alert(now, &event.path));
                }
            }

            // Mass file modification pattern — many different files modified in short window
            // (distinct from burst_file_activity which counts any file ops)
            if event.kind == "file_modified" {
                let parent_dir = event.path.rsplit('/').nth(1)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| event.path.clone());

                let timestamps = self.modification_counts
                    .entry(parent_dir.clone())
                    .or_insert_with(Vec::new);
                timestamps.retain(|t| now.signed_duration_since(*t).num_seconds() <= self.window_seconds);
                timestamps.push(event.timestamp);

                // Fire at 30+ modifications in window — threshold above normal save behavior
                if timestamps.len() >= 30 {
                    alerts.push(build_mass_modification_alert(
                        now,
                        &event.path,
                        &parent_dir,
                        timestamps.len(),
                        self.window_seconds,
                    ));
                    timestamps.clear();
                }
            }
        }

        // Prune stale entries to prevent unbounded memory growth
        self.ransomware_extension_counts.retain(|_, v| !v.is_empty());
        self.modification_counts.retain(|_, v| !v.is_empty());

        alerts
    }

    /// Reset alert state (e.g. after incident is acknowledged).
    pub fn reset_ransomware_alert_state(&mut self) {
        self.ransomware_alert_fired = false;
    }
}

fn build_ransomware_wave_alert(
    now: DateTime<Utc>,
    path: &str,
    count: usize,
    window_seconds: i64,
) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        "alert_ransomware_rename_wave",
        "core-agent/filesystem-anomaly",
        json!({
            "severity": AlertSeverity::Critical.as_str(),
            "score": AlertSeverity::Critical.score(),
            "category": "ransomware",
            "reason": format!(
                "{} files with ransomware extensions appeared in {}s — active encryption in progress",
                count, window_seconds
            ),
            "details": {
                "path": path,
                "encrypted_file_count": count,
                "window_seconds": window_seconds,
                "mitre_technique": "T1486",
                "confidence": "high",
            }
        }),
    )
}

fn build_ransom_note_alert(now: DateTime<Utc>, path: &str) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        "alert_ransom_note_created",
        "core-agent/filesystem-anomaly",
        json!({
            "severity": AlertSeverity::Critical.as_str(),
            "score": AlertSeverity::Critical.score(),
            "category": "ransomware",
            "reason": "Ransom note file created — ransomware attack in progress",
            "details": {
                "path": path,
                "mitre_technique": "T1486",
                "confidence": "high",
            }
        }),
    )
}

fn build_mass_modification_alert(
    now: DateTime<Utc>,
    path: &str,
    directory: &str,
    count: usize,
    window_seconds: i64,
) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        "alert_mass_file_rw_pattern",
        "core-agent/filesystem-anomaly",
        json!({
            "severity": AlertSeverity::High.as_str(),
            "score": AlertSeverity::High.score(),
            "category": "impact",
            "reason": format!(
                "{} file modifications in {}s in directory '{}' — mass read-write pattern",
                count, window_seconds, directory
            ),
            "details": {
                "path": path,
                "directory": directory,
                "modification_count": count,
                "window_seconds": window_seconds,
                "mitre_technique": "T1485",
                "confidence": "medium",
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_event(kind: &str, path: &str, offset_ms: i64) -> FileEventRecord {
        FileEventRecord {
            kind: kind.to_string(),
            path: path.to_string(),
            timestamp: Utc::now() + Duration::milliseconds(offset_ms),
            size_bytes: 1024,
            is_executable: false,
            has_quarantine: false,
            quarantine_value: None,
            magic_bytes_hint: None,
        }
    }

    #[test]
    fn ransomware_wave_fires_at_five_encrypted_files() {
        let now = Utc::now();
        let mut detector = FilesystemAnomalyDetector::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        let events: Vec<FileEventRecord> = (0..5)
            .map(|i| make_event("file_created", &format!("{}/Documents/file{}.encrypted", home, i), 0))
            .collect();

        let alerts = detector.process_events(&events, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_ransomware_rename_wave"),
            "5 .encrypted files in window should fire ransomware wave alert"
        );
    }

    #[test]
    fn ransomware_wave_does_not_fire_for_four_files() {
        let now = Utc::now();
        let mut detector = FilesystemAnomalyDetector::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        let events: Vec<FileEventRecord> = (0..4)
            .map(|i| make_event("file_created", &format!("{}/Documents/file{}.encrypted", home, i), 0))
            .collect();

        let alerts = detector.process_events(&events, now);
        assert!(
            alerts.iter().all(|e| e.event_type != "alert_ransomware_rename_wave"),
            "4 .encrypted files should NOT fire ransomware wave alert"
        );
    }

    #[test]
    fn ransom_note_fires_for_readme_txt() {
        let now = Utc::now();
        let mut detector = FilesystemAnomalyDetector::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        let events = vec![make_event(
            "file_created",
            &format!("{}/Desktop/README.TXT", home),
            0,
        )];
        let alerts = detector.process_events(&events, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_ransom_note_created"),
            "readme.txt creation should fire ransom note alert"
        );
    }

    #[test]
    fn ransom_note_does_not_fire_for_normal_readme() {
        let now = Utc::now();
        let mut detector = FilesystemAnomalyDetector::new();

        // A README.md in a code project should NOT fire
        let events = vec![make_event(
            "file_created",
            "/Users/dev/Projects/myapp/README.md",
            0,
        )];
        let alerts = detector.process_events(&events, now);
        assert!(
            alerts.iter().all(|e| e.event_type != "alert_ransom_note_created"),
            "README.md in code project should NOT fire ransom note alert"
        );
    }

    #[test]
    fn mass_modification_fires_at_threshold() {
        let now = Utc::now();
        let mut detector = FilesystemAnomalyDetector::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        let events: Vec<FileEventRecord> = (0..30)
            .map(|i| make_event("file_modified", &format!("{}/Documents/file{}.txt", home, i), 0))
            .collect();

        let alerts = detector.process_events(&events, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_mass_file_rw_pattern"),
            "30 file modifications should fire mass rw pattern alert"
        );
    }

    #[test]
    fn mass_modification_does_not_fire_below_threshold() {
        let now = Utc::now();
        let mut detector = FilesystemAnomalyDetector::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        let events: Vec<FileEventRecord> = (0..29)
            .map(|i| make_event("file_modified", &format!("{}/Documents/file{}.txt", home, i), 0))
            .collect();

        let alerts = detector.process_events(&events, now);
        assert!(
            alerts.iter().all(|e| e.event_type != "alert_mass_file_rw_pattern"),
            "29 file modifications should NOT fire mass rw pattern alert"
        );
    }
}
