/// Per-subsystem performance profiling.
///
/// Each main-loop iteration times six subsystems:
///   file_monitor, process_monitor, persistence_monitor, network_monitor,
///   detection_eval, incident_correlation
///
/// Every FLUSH_INTERVAL_LOOPS iterations, aggregate stats are written to
/// `runtime/logs/perf-stats.jsonl`.  A `--perf-report` flag causes the agent
/// to print a human-readable summary on exit.

use std::collections::HashMap;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

pub const FLUSH_INTERVAL_LOOPS: u64 = 120; // ~30 seconds at 250ms cadence
const PERF_LOG_RELATIVE: &str = "runtime/logs/perf-stats.jsonl";

/// Absolute path to perf-stats.jsonl, resolved the same way as all other log paths.
fn perf_log_path() -> PathBuf {
    crate::logging::resolve_project_root().join(PERF_LOG_RELATIVE)
}

/// Aggregate stats for one subsystem over the flush window.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SubsystemStats {
    pub name: String,
    pub samples: u64,
    pub total_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
    pub p95_us: u64,
}

/// Rolling sample accumulator — one instance per subsystem, held in `PerfTracker`.
struct SubsystemAccumulator {
    name: &'static str,
    samples: Vec<u64>,
}

impl SubsystemAccumulator {
    fn new(name: &'static str) -> Self {
        Self { name, samples: Vec::with_capacity(FLUSH_INTERVAL_LOOPS as usize + 4) }
    }

    fn record(&mut self, elapsed_us: u64) {
        self.samples.push(elapsed_us);
    }

    fn flush(&mut self) -> SubsystemStats {
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        let count = sorted.len() as u64;
        let total: u64 = sorted.iter().sum();
        let min = sorted.first().copied().unwrap_or(0);
        let max = sorted.last().copied().unwrap_or(0);
        let mean = if count > 0 { total / count } else { 0 };
        let p95 = if sorted.is_empty() {
            0
        } else {
            let idx = ((sorted.len() as f64) * 0.95) as usize;
            sorted[idx.min(sorted.len() - 1)]
        };

        let stats = SubsystemStats {
            name: self.name.to_string(),
            samples: count,
            total_us: total,
            min_us: min,
            max_us: max,
            mean_us: mean,
            p95_us: p95,
        };

        self.samples.clear();
        stats
    }
}

/// Central performance tracker — create one per agent run.
pub struct PerfTracker {
    accumulators: HashMap<&'static str, SubsystemAccumulator>,
    loop_count: u64,
    /// Optional RSS baseline captured at startup (bytes).
    rss_baseline_bytes: Option<u64>,
    /// CPU throttle: if any subsystem exceeds this threshold in a single loop,
    /// the main loop sleeps an extra `throttle_extra_ms` before the next iteration.
    throttle_threshold_us: u64,
    throttle_extra_ms: u64,
}

impl PerfTracker {
    pub fn new(throttle_threshold_us: u64, throttle_extra_ms: u64) -> Self {
        let subsystems = [
            "file_monitor",
            "process_monitor",
            "persistence_monitor",
            "network_monitor",
            "detection_eval",
            "incident_correlation",
        ];
        let mut accumulators = HashMap::new();
        for name in &subsystems {
            accumulators.insert(*name, SubsystemAccumulator::new(name));
        }
        Self {
            accumulators,
            loop_count: 0,
            rss_baseline_bytes: None,
            throttle_threshold_us,
            throttle_extra_ms,
        }
    }

    /// Call once at startup to establish an RSS baseline.
    pub fn capture_rss_baseline(&mut self) {
        self.rss_baseline_bytes = rss_bytes();
    }

    /// Record a raw duration.
    pub fn record_raw(&mut self, subsystem: &'static str, elapsed: Duration) {
        let us = elapsed.as_micros() as u64;
        if let Some(acc) = self.accumulators.get_mut(subsystem) {
            acc.record(us);
        }
    }

    /// Increment loop counter and return `true` if it's time to flush.
    pub fn tick(&mut self) -> bool {
        self.loop_count += 1;
        self.loop_count % FLUSH_INTERVAL_LOOPS == 0
    }

    /// Returns how many extra milliseconds to sleep if any subsystem was hot this loop.
    pub fn throttle_extra_sleep_ms(&self) -> u64 {
        for acc in self.accumulators.values() {
            if let Some(&last) = acc.samples.last() {
                if last > self.throttle_threshold_us {
                    return self.throttle_extra_ms;
                }
            }
        }
        0
    }

    /// Flush aggregate stats to `runtime/logs/perf-stats.jsonl` and reset accumulators.
    pub fn flush(&mut self, now: &chrono::DateTime<chrono::Utc>) {
        let stats: Vec<SubsystemStats> = self
            .accumulators
            .values_mut()
            .map(|acc| acc.flush())
            .collect();

        let rss_current = rss_bytes();
        let rss_delta = match (self.rss_baseline_bytes, rss_current) {
            (Some(baseline), Some(current)) => {
                Some(current as i64 - baseline as i64)
            }
            _ => None,
        };

        let record = serde_json::json!({
            "timestamp": now.to_rfc3339(),
            "loop_count": self.loop_count,
            "subsystems": stats,
            "rss_bytes": rss_current,
            "rss_baseline_bytes": self.rss_baseline_bytes,
            "rss_delta_bytes": rss_delta,
        });

        append_perf_record(&record);
    }

    /// Print a human-readable summary to stdout.  Called when `--perf-report` is passed.
    /// The caller is responsible for calling `flush()` before this — do NOT flush here or
    /// the accumulators will already be empty and the report will show all zeros.
    pub fn print_report(&self) {
        // Re-read and pretty-print the last line of the perf log.
        let path = perf_log_path();
        if !path.exists() {
            println!("[perf] no data — perf-stats.jsonl not found at {}", path.display());
            return;
        }

        println!("\n╔═══════════════════════════════════════════════════╗");
        println!("║        Agent Security — Performance Report         ║");
        println!("╚═══════════════════════════════════════════════════╝\n");

        let content = std::fs::read_to_string(path).unwrap_or_default();
        for line in content.lines().rev().take(1) {
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
                println!("  Loop count:     {}", record["loop_count"]);
                println!("  RSS current:    {} kB", record["rss_bytes"].as_u64().unwrap_or(0) / 1024);
                if let Some(delta) = record["rss_delta_bytes"].as_i64() {
                    println!("  RSS delta:      {:+} kB", delta / 1024);
                }
                println!();
                println!("  {:<28} {:>8}  {:>8}  {:>8}  {:>8}", "Subsystem", "mean(µs)", "p95(µs)", "min(µs)", "max(µs)");
                println!("  {}", "─".repeat(68));
                if let Some(subsystems) = record["subsystems"].as_array() {
                    let mut rows: Vec<&serde_json::Value> = subsystems.iter().collect();
                    rows.sort_by_key(|v| {
                        std::cmp::Reverse(v["mean_us"].as_u64().unwrap_or(0))
                    });
                    for s in rows {
                        println!(
                            "  {:<28} {:>8}  {:>8}  {:>8}  {:>8}",
                            s["name"].as_str().unwrap_or("?"),
                            s["mean_us"].as_u64().unwrap_or(0),
                            s["p95_us"].as_u64().unwrap_or(0),
                            s["min_us"].as_u64().unwrap_or(0),
                            s["max_us"].as_u64().unwrap_or(0),
                        );
                    }
                }
            }
        }
        println!();
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn append_perf_record(record: &serde_json::Value) {
    let path = perf_log_path();
    eprintln!("[perf] flushing to {}", path.display());

    if let Some(dir) = path.parent() {
        if let Err(e) = create_dir_all(dir) {
            eprintln!("[perf] failed to create log dir {}: {e}", dir.display());
            return;
        }
    }

    match serde_json::to_string(record) {
        Err(e) => eprintln!("[perf] failed to serialize record: {e}"),
        Ok(serialized) => match OpenOptions::new().create(true).append(true).open(&path) {
            Err(e) => eprintln!("[perf] failed to open {}: {e}", path.display()),
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{serialized}") {
                    eprintln!("[perf] failed to write record: {e}");
                }
            }
        },
    }
}

/// Read resident set size from macOS task_info via `/proc/self/status` fallback.
/// On macOS, `ps -o rss= -p <pid>` is the portable approach.
fn rss_bytes() -> Option<u64> {
    let pid = std::process::id();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let kb: u64 = stdout.trim().parse().ok()?;
    Some(kb * 1024) // ps reports RSS in kB on macOS
}

