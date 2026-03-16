use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

#[derive(Serialize)]
struct TelemetryEvent {
    id: String,
    timestamp: u64,
    event_type: String,
    source: String,
    payload: serde_json::Value,
}

#[derive(Clone, Debug)]
struct FileSnapshot {
    modified_unix: u64,
    size: u64,
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    pid: String,
    command: String,
    args: String,
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn write_event(event: &TelemetryEvent, log_file: &PathBuf) {
    let json = serde_json::to_string(event).unwrap();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .expect("failed to open log file");

    writeln!(file, "{}", json).unwrap();
}

fn get_process_list() -> HashMap<String, ProcessInfo> {
    let output = Command::new("ps")
        .arg("-axo")
        .arg("pid=,comm=,args=")
        .output()
        .expect("failed to run ps");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = HashMap::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let pid = parts[0].to_string();
        let command = parts[1].to_string();
        let args = if parts.len() > 2 {
            parts[2..].join(" ")
        } else {
            command.clone()
        };

        if command == "ps" || command.ends_with("/ps") {
            continue;
        }

        processes.insert(
            pid.clone(),
            ProcessInfo {
                pid,
                command,
                args,
            },
        );
    }

    processes
}

fn get_home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .expect("HOME environment variable not set")
}

fn monitored_directories() -> Vec<PathBuf> {
    let home = get_home_dir();

    vec![
        home.join("Downloads"),
        home.join("Desktop"),
        home.join("Documents"),
    ]
}

fn downloads_dir() -> PathBuf {
    get_home_dir().join("Downloads")
}

fn file_snapshot_for_path(path: &Path) -> Option<FileSnapshot> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }

    let modified = metadata.modified().ok()?;
    let modified_unix = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();

    Some(FileSnapshot {
        modified_unix,
        size: metadata.len(),
    })
}

fn scan_files(paths: &[PathBuf]) -> HashMap<String, FileSnapshot> {
    let mut snapshots = HashMap::new();

    for dir in paths {
        if !dir.exists() {
            continue;
        }

        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();

            if let Some(snapshot) = file_snapshot_for_path(path) {
                snapshots.insert(path.to_string_lossy().to_string(), snapshot);
            }
        }
    }

    snapshots
}

fn track_recent_download(path: &str, downloads: &Path, recent_downloads: &mut HashMap<String, u64>) {
    let path_buf = PathBuf::from(path);
    if path_buf.starts_with(downloads) {
        recent_downloads.insert(path.to_string(), unix_timestamp());
    }
}

fn record_file_activity_and_maybe_alert(
    path: &str,
    log_file: &PathBuf,
    recent_file_activity: &mut VecDeque<(String, u64)>,
) {
    if path.ends_with(".DS_Store") {
        return;
    }

    let now = unix_timestamp();
    recent_file_activity.push_back((path.to_string(), now));

    while let Some((_, ts)) = recent_file_activity.front() {
        if now.saturating_sub(*ts) > 10 {
            recent_file_activity.pop_front();
        } else {
            break;
        }
    }

    if recent_file_activity.len() >= 12 {
        let alert = TelemetryEvent {
            id: format!("alert-burst-file-activity-{}", now),
            timestamp: now,
            event_type: "alert".to_string(),
            source: "core-agent".to_string(),
            payload: serde_json::json!({
                "rule_id": "burst_file_activity",
                "severity": "high",
                "title": "Suspicious burst of file activity",
                "summary": "Multiple files were created or modified rapidly. This may indicate ransomware or destructive automation.",
                "count": recent_file_activity.len()
            }),
        };

        println!(
            "ALERT: burst file activity detected ({} files)",
            recent_file_activity.len()
        );

        write_event(&alert, log_file);
        recent_file_activity.clear();
    }
}

fn emit_file_events(
    known_files: &mut HashMap<String, FileSnapshot>,
    watch_paths: &[PathBuf],
    log_file: &PathBuf,
    recent_downloads: &mut HashMap<String, u64>,
    recent_file_activity: &mut VecDeque<(String, u64)>,
) {
    let current = scan_files(watch_paths);
    let downloads = downloads_dir();

    for (path, snapshot) in &current {
        match known_files.get(path) {
            None => {
                let ts = unix_timestamp();

                let event = TelemetryEvent {
                    id: format!("file-create-{}-{}", path.replace('/', "_"), ts),
                    timestamp: ts,
                    event_type: "file_create".to_string(),
                    source: "core-agent".to_string(),
                    payload: serde_json::json!({
                        "path": path,
                        "size": snapshot.size,
                        "modified_unix": snapshot.modified_unix
                    }),
                };

                println!("New file detected: {}", path);
                write_event(&event, log_file);
                track_recent_download(path, &downloads, recent_downloads);
                record_file_activity_and_maybe_alert(path, log_file, recent_file_activity);
            }
            Some(old_snapshot) => {
                if old_snapshot.modified_unix != snapshot.modified_unix
                    || old_snapshot.size != snapshot.size
                {
                    let ts = unix_timestamp();

                    let event = TelemetryEvent {
                        id: format!("file-modify-{}-{}", path.replace('/', "_"), ts),
                        timestamp: ts,
                        event_type: "file_modify".to_string(),
                        source: "core-agent".to_string(),
                        payload: serde_json::json!({
                            "path": path,
                            "old_size": old_snapshot.size,
                            "new_size": snapshot.size,
                            "old_modified_unix": old_snapshot.modified_unix,
                            "new_modified_unix": snapshot.modified_unix
                        }),
                    };

                    println!("Modified file detected: {}", path);
                    write_event(&event, log_file);
                    track_recent_download(path, &downloads, recent_downloads);
                    record_file_activity_and_maybe_alert(path, log_file, recent_file_activity);
                }
            }
        }
    }

    *known_files = current;
}

fn emit_process_events(
    known_processes: &mut HashSet<String>,
    log_file: &PathBuf,
    recent_downloads: &mut HashMap<String, u64>,
) {
    let current = get_process_list();
    let now = unix_timestamp();

    recent_downloads.retain(|_, seen_ts| now.saturating_sub(*seen_ts) <= 3600);

    for (pid, proc_info) in &current {
        if known_processes.contains(pid) {
            continue;
        }

        let ts = unix_timestamp();

        let event = TelemetryEvent {
            id: format!("proc-{}-{}", pid, ts),
            timestamp: ts,
            event_type: "process_start".to_string(),
            source: "core-agent".to_string(),
            payload: serde_json::json!({
                "pid": proc_info.pid,
                "command": proc_info.command,
                "args": proc_info.args
            }),
        };

        println!(
            "New process detected: pid={} command={} args={}",
            proc_info.pid, proc_info.command, proc_info.args
        );
        write_event(&event, log_file);

        for download_path in recent_downloads.keys() {
            if proc_info.command == *download_path || proc_info.args.contains(download_path) {
                let alert = TelemetryEvent {
                    id: format!("alert-download-exec-{}-{}", pid, ts),
                    timestamp: ts,
                    event_type: "alert".to_string(),
                    source: "core-agent".to_string(),
                    payload: serde_json::json!({
                        "rule_id": "suspicious_download_execution",
                        "severity": "high",
                        "title": "Downloaded file executed",
                        "summary": "A file recently created or modified in Downloads was executed.",
                        "pid": proc_info.pid,
                        "command": proc_info.command,
                        "args": proc_info.args,
                        "matched_download": download_path
                    }),
                };

                println!("ALERT: Downloaded file executed: {}", download_path);
                write_event(&alert, log_file);
            }
        }
    }

    *known_processes = current.keys().cloned().collect();
}

fn main() {
    println!("Core Agent Starting...");

    let root = project_root();
    let logs_dir = root.join("runtime").join("logs");

    create_dir_all(&logs_dir).unwrap();

    let log_file = logs_dir.join("agent-events.jsonl");
    let watch_paths = monitored_directories();

    println!("Watching directories:");
    for path in &watch_paths {
        println!("  - {}", path.display());
    }

    let initial_processes = get_process_list();
    let mut known_processes: HashSet<String> = initial_processes.keys().cloned().collect();
    let mut known_files = scan_files(&watch_paths);
    let mut recent_downloads: HashMap<String, u64> = HashMap::new();
    let mut recent_file_activity: VecDeque<(String, u64)> = VecDeque::new();

    loop {
        emit_file_events(
            &mut known_files,
            &watch_paths,
            &log_file,
            &mut recent_downloads,
            &mut recent_file_activity,
        );

        emit_process_events(&mut known_processes, &log_file, &mut recent_downloads);

        thread::sleep(Duration::from_secs(1));
    }
}