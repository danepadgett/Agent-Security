/// Cryptomining Detection — Tranche 3 Upgrade 4
///
/// Detects known miner binaries, mining pool connections (by port and domain),
/// mining-specific CLI arguments, and processes with mining argument patterns.
///
/// MITRE coverage:
///   T1496 — Resource Hijacking
use crate::models::{AlertSeverity, ProcessInfo, TelemetryEvent};
use chrono::DateTime;
use chrono::Utc;
use serde_json::json;
use std::path::Path;

fn mining_alert(
    now: DateTime<Utc>,
    event_type: &str,
    severity: AlertSeverity,
    reason: &str,
    process: &ProcessInfo,
    trigger: &str,
) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        event_type,
        "core-agent/cryptomining",
        json!({
            "severity": severity.as_str(),
            "score": severity.score(),
            "category": "cryptomining",
            "reason": reason,
            "details": {
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "parent_command": process.parent_command,
                "parent_process_kind": process.parent_process_kind,
                "trigger": trigger,
                "mitre_technique": "T1496",
                "confidence": "high",
            }
        }),
    )
}

/// Known cryptominer binary names (substrings to match against basename).
const MINER_BINARY_NAMES: &[&str] = &[
    "xmrig", "cpuminer", "minerd", "bfgminer", "cgminer", "ethminer",
    "nbminer", "lolminer", "t-rex", "gminer", "phoenixminer", "claymore",
    "nanominer", "srb-miner", "srbminer", "teamredminer", "kawpow",
    "monerod", "xmr-stak",
];

/// Mining pool ports commonly used by Stratum protocol and popular pools.
/// Note: 4444 overlaps with RAT ports — only treat as mining if combined with other signals.
const MINING_PORTS: &[u16] = &[3333, 3334, 14444, 14433, 45560, 8008, 8080, 80, 443];
/// These ports are strongly associated with mining even standalone.
const STRONG_MINING_PORTS: &[u16] = &[3333, 3334, 14444, 14433, 45560];

/// Mining-specific argument patterns.
fn has_mining_args(args_lower: &str) -> bool {
    // Stratum protocol URLs
    if args_lower.contains("stratum+tcp://")
        || args_lower.contains("stratum+ssl://")
        || args_lower.contains("stratum2+tcp://")
    {
        return true;
    }
    // Common mining algorithm flags
    if args_lower.contains("--algo=rx/") || args_lower.contains("-a rx/")
        || args_lower.contains("--algo=cryptonight")
        || args_lower.contains("--coin=xmr") || args_lower.contains("--coin xmr")
        || args_lower.contains("--coin=monero")
    {
        return true;
    }
    // Common mining pool flags
    if (args_lower.contains("--pool") || args_lower.contains("-o "))
        && (args_lower.contains("xmrpool") || args_lower.contains("minexmr")
            || args_lower.contains("pool.supportxmr") || args_lower.contains("moneroocean")
            || args_lower.contains("nanopool") || args_lower.contains("2miners")
            || args_lower.contains("f2pool") || args_lower.contains("ethermine")
            || args_lower.contains("dwarfpool") || args_lower.contains("miningpoolhub"))
    {
        return true;
    }
    // Wallet address patterns: Monero (long hex), Ethereum (0x...)
    if (args_lower.contains("--wallet") || args_lower.contains("-u "))
        && (args_lower.contains("0x") || args_lower.len() > 95)
    {
        return true;
    }
    false
}

/// Detect cryptomining patterns from a ProcessInfo.
pub fn detect_cryptomining(process: &ProcessInfo, now: DateTime<Utc>) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    let cmd_basename = Path::new(&process.command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let args_lower = process.args.to_ascii_lowercase();
    let parent_kind = process.parent_process_kind.as_deref().unwrap_or("");

    // ── Known miner binary ────────────────────────────────────────────────────

    let is_known_miner = MINER_BINARY_NAMES.iter().any(|m| cmd_basename.contains(m));

    if is_known_miner {
        alerts.push(mining_alert(
            now,
            "alert_miner_process_detected",
            AlertSeverity::Critical,
            "Known cryptominer binary executing — resource hijacking",
            process,
            "known_miner_binary",
        ));
        // Also fire args alert if mining args present (belt-and-suspenders for scoring)
        if has_mining_args(&args_lower) {
            alerts.push(mining_alert(
                now,
                "alert_miner_args_detected",
                AlertSeverity::Critical,
                "Known miner binary with mining pool/algorithm arguments — confirmed resource hijacking",
                process,
                "miner_args_confirmed",
            ));
        }
        return alerts; // miner binary covers it all
    }

    // ── Mining-specific arguments in any process ──────────────────────────────

    if has_mining_args(&args_lower) {
        // Only alert from non-system, non-browser processes
        if process.process_kind != "system" && process.process_kind != "browser" {
            alerts.push(mining_alert(
                now,
                "alert_miner_args_detected",
                AlertSeverity::Critical,
                "Process arguments contain mining pool URL or algorithm flags — cryptominer",
                process,
                "mining_args",
            ));
        }
        return alerts;
    }

    // ── Mining pool port connections via args (nc, curl, openssl) ────────────

    // nc / ncat / netcat connecting to known mining ports
    if cmd_basename == "nc" || cmd_basename == "ncat" || cmd_basename == "netcat" {
        let port_in_args = |port: u16| {
            let ps = port.to_string();
            args_lower.ends_with(&ps) || args_lower.contains(&format!(" {} ", ps))
        };
        if STRONG_MINING_PORTS.iter().any(|p| port_in_args(*p)) {
            alerts.push(mining_alert(
                now,
                "alert_mining_pool_connection",
                AlertSeverity::High,
                "nc/ncat connecting to mining pool port (Stratum protocol) — possible cryptomining",
                process,
                "nc_mining_port",
            ));
        }
    }

    // curl connecting to stratum (even though curl doesn't do stratum, some loaders do)
    if cmd_basename == "curl" && args_lower.contains("stratum") {
        alerts.push(mining_alert(
            now,
            "alert_mining_pool_connection",
            AlertSeverity::High,
            "curl referencing stratum mining protocol — cryptomining loader",
            process,
            "curl_stratum",
        ));
    }

    // openssl connecting to port 3333 / 14444 from interpreter chain
    if (cmd_basename == "openssl" || cmd_basename == "openssl_s_client")
        && (parent_kind == "interpreter" || parent_kind == "unknown")
    {
        let port_in_args = |port: u16| {
            let ps = format!("-port {}", port);
            let ps2 = format!(":{}", port);
            args_lower.contains(&ps) || args_lower.contains(&ps2)
        };
        if STRONG_MINING_PORTS.iter().any(|p| port_in_args(*p)) {
            alerts.push(mining_alert(
                now,
                "alert_mining_pool_connection",
                AlertSeverity::High,
                "openssl s_client connecting to mining pool port from interpreter chain",
                process,
                "openssl_mining_port",
            ));
        }
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify_path;
    use crate::command_features::extract_features;
    use chrono::Utc;

    fn make_process(
        command: &str,
        args: &str,
        process_kind: &str,
        parent_kind: Option<&str>,
        parent_command: Option<&str>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid: 3000,
            ppid: 500,
            command: command.to_string(),
            args: args.to_string(),
            process_kind: process_kind.to_string(),
            command_path_kind: classify_path(command),
            parent_command: parent_command.map(|s| s.to_string()),
            parent_args: None,
            parent_process_kind: parent_kind.map(|s| s.to_string()),
            parent_command_path_kind: None,
            behavior: extract_features(command, args),
        }
    }

    #[test]
    fn known_miner_binary_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/xmrig",
            "--algo=rx/0 -o stratum+tcp://pool.minexmr.com:5555 -u 4Abc...",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_cryptomining(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_miner_process_detected"),
            "xmrig should fire miner process detected"
        );
    }

    #[test]
    fn stratum_url_in_args_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/worker",
            "-o stratum+tcp://pool.supportxmr.com:3333 -u 4A...",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_cryptomining(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_miner_args_detected"),
            "stratum+tcp:// in args should fire miner args alert"
        );
    }

    #[test]
    fn nc_to_mining_port_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/nc",
            "pool.minexmr.com 3333",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_cryptomining(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_mining_pool_connection"),
            "nc to port 3333 should fire mining pool connection"
        );
    }

    #[test]
    fn cpuminer_name_fires() {
        let now = Utc::now();
        let p = make_process(
            "/tmp/cpuminer-multi",
            "--algo=cryptonight -o stratum+tcp://moneroocean.stream:10128",
            "user_app",
            Some("unknown"),
            None,
        );
        let alerts = detect_cryptomining(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_miner_process_detected"),
            "cpuminer should fire miner process detected"
        );
    }

    #[test]
    fn normal_curl_download_does_not_fire() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/curl",
            "-o /tmp/output.txt https://example.com/file.txt",
            "user_app",
            Some("user_app"),
            Some("/Applications/Terminal.app/Contents/MacOS/Terminal"),
        );
        let alerts = detect_cryptomining(&p, now);
        assert!(
            alerts.is_empty(),
            "Normal curl download should not fire any mining alerts"
        );
    }

    #[test]
    fn nc_to_non_mining_port_does_not_fire() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/nc",
            "example.com 8443",
            "user_app",
            Some("user_app"),
            Some("/Applications/Terminal.app/Contents/MacOS/Terminal"),
        );
        let alerts = detect_cryptomining(&p, now);
        assert!(
            alerts.is_empty(),
            "nc to port 8443 should not fire mining alert"
        );
    }
}
