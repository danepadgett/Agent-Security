/// Agent Security — watchdog process.
///
/// Monitors the core-agent process and restarts it if it exits unexpectedly.
///
/// Usage:
///   watchdog [--agent-path /path/to/core-agent] [--log-path runtime/logs/watchdog.log]
///
/// The watchdog should be started as a separate long-running process (e.g., via a
/// LaunchDaemon plist).  It polls every POLL_INTERVAL_SECS and records restart
/// events to a dedicated log file.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const POLL_INTERVAL_SECS: u64 = 5;
const MAX_RESTARTS_PER_HOUR: u32 = 10;
const WATCHDOG_LOG_FILE: &str = "runtime/logs/watchdog.log";
const AGENT_PROCESS_NAME: &str = "core-agent";

fn main() {
    let args: Vec<String> = env::args().collect();

    let agent_path = parse_arg(&args, "--agent-path")
        .unwrap_or_else(|| "./target/release/core-agent".to_string());

    let log_path = parse_arg(&args, "--log-path")
        .unwrap_or_else(|| WATCHDOG_LOG_FILE.to_string());

    ensure_log_dir(&log_path);

    log_event(&log_path, "watchdog_started", &format!("monitoring agent at {agent_path}"));

    let mut restart_count: u32 = 0;
    let mut hour_window_start = unix_ts();

    loop {
        thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));

        let now = unix_ts();

        // Reset hourly restart counter.
        if now - hour_window_start >= 3600 {
            restart_count = 0;
            hour_window_start = now;
        }

        if is_agent_running() {
            continue;
        }

        log_event(&log_path, "agent_down_detected", "core-agent process not found");

        if restart_count >= MAX_RESTARTS_PER_HOUR {
            log_event(
                &log_path,
                "restart_suppressed",
                &format!(
                    "restart limit {MAX_RESTARTS_PER_HOUR}/hour reached — not restarting to avoid crash loop"
                ),
            );
            continue;
        }

        log_event(
            &log_path,
            "agent_restart_attempt",
            &format!("spawning {agent_path} (restart #{restart_count})"),
        );

        match spawn_agent(&agent_path) {
            Ok(child_pid) => {
                restart_count += 1;
                log_event(
                    &log_path,
                    "agent_restarted",
                    &format!("core-agent restarted with pid={child_pid} restart_count={restart_count}"),
                );
            }
            Err(e) => {
                log_event(
                    &log_path,
                    "restart_failed",
                    &format!("failed to start {agent_path}: {e}"),
                );
            }
        }
    }
}

fn is_agent_running() -> bool {
    // Use pgrep which is available on all macOS versions.
    // -x: exact process name match.
    let output = Command::new("pgrep")
        .arg("-x")
        .arg(AGENT_PROCESS_NAME)
        .output();

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn spawn_agent(agent_path: &str) -> Result<u32, String> {
    let path = Path::new(agent_path);
    if !path.exists() {
        return Err(format!("binary not found at {agent_path}"));
    }

    // Spawn detached — we don't wait on the child.
    let child = Command::new(agent_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Run in the project root directory so relative runtime/ paths resolve correctly.
        .current_dir(
            path.parent()
                .and_then(|p| p.parent())  // target/release → target → project root
                .and_then(|p| p.parent())
                .unwrap_or(Path::new(".")),
        )
        .spawn()
        .map_err(|e| e.to_string())?;

    Ok(child.id())
}

fn log_event(log_path: &str, event_type: &str, detail: &str) {
    let ts = unix_ts();
    let line = format!("{{\"ts\":{ts},\"event\":\"{event_type}\",\"detail\":\"{detail}\"}}\n");

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = file.write_all(line.as_bytes());
    }

    eprintln!("[watchdog] {event_type}: {detail}");
}

fn ensure_log_dir(log_path: &str) {
    if let Some(parent) = Path::new(log_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}
