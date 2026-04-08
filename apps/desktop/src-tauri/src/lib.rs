use chrono;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use tauri::{AppHandle, Emitter, Manager};
use urlencoding;

// ── Path helpers ─────────────────────────────────────────────────────────────

/// Resolve the project root at runtime.
///
/// Resolution order:
///   1. `$HOUND_ROOT` env var — explicit override, useful when the
///      app is run from an unexpected working directory.
///   2. `CARGO_MANIFEST_DIR` (baked in at compile time) navigated three
///      levels up: src-tauri → desktop → apps → project-root.
///      This is correct for all `npm run tauri dev` invocations.
///
/// Returns `Err` with a human-readable message if neither strategy works.
fn project_root() -> Result<PathBuf, String> {
    // 1. Explicit environment variable override
    if let Ok(root) = std::env::var("HOUND_ROOT") {
        let path = PathBuf::from(&root);
        if path.is_dir() {
            return Ok(path);
        }
        eprintln!(
            "[hound] WARNING: HOUND_ROOT={root} is not a directory, ignoring"
        );
    }

    // 2. Compile-time path: CARGO_MANIFEST_DIR is the absolute path to src-tauri/.
    //    Layout: <root>/apps/desktop/src-tauri — go up 3 levels.
    let compile_time_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // src-tauri → desktop
        .and_then(|p| p.parent()) // desktop → apps
        .and_then(|p| p.parent()) // apps → project root
        .map(|p| p.to_path_buf());

    if let Some(path) = compile_time_root {
        if path.is_dir() {
            return Ok(path);
        }
        return Err(format!(
            "compile-time project root {} does not exist on disk — \
             set HOUND_ROOT env var to override",
            path.display()
        ));
    }

    Err("failed to derive project root from CARGO_MANIFEST_DIR — \
         set HOUND_ROOT env var"
        .to_string())
}

fn log_file_path() -> Result<PathBuf, String> {
    Ok(project_root()?
        .join("runtime")
        .join("logs")
        .join("agent-events.jsonl"))
}

fn ack_file_path() -> Result<PathBuf, String> {
    Ok(project_root()?
        .join("runtime")
        .join("acknowledged-incidents.json"))
}

fn config_file_path() -> Result<PathBuf, String> {
    Ok(project_root()?.join("runtime").join("agent-config.toml"))
}

/// Ensure the runtime directory tree exists and the log file is present.
/// Creates empty files/dirs as needed so the watcher always has something to watch.
fn ensure_runtime_dirs() -> Result<PathBuf, String> {
    let log_path = log_file_path()?;

    if let Some(dir) = log_path.parent() {
        fs::create_dir_all(dir).map_err(|e| {
            format!(
                "failed to create runtime/logs dir at {}: {e}",
                dir.display()
            )
        })?;
    }

    // Touch the log file so the watcher has a file to stat immediately.
    if !log_path.exists() {
        fs::write(&log_path, b"").map_err(|e| {
            format!(
                "failed to create empty log file at {}: {e}",
                log_path.display()
            )
        })?;
        eprintln!(
            "[hound] created empty log file: {}",
            log_path.display()
        );
    }

    Ok(log_path)
}

// ── Commands ─────────────────────────────────────────────────────────────────

#[tauri::command]
fn get_log_path() -> String {
    match log_file_path() {
        Ok(p) => p.display().to_string(),
        Err(e) => format!("error: {e}"),
    }
}

#[tauri::command]
fn read_agent_events() -> Result<Vec<String>, String> {
    let log_file = log_file_path()?;
    if !log_file.exists() {
        return Ok(vec![]);
    }

    const TAIL_BYTES: u64 = 1_024 * 1_024; // 1 MB
    const MAX_LINES: usize = 2000;

    let mut file = fs::File::open(&log_file)
        .map_err(|e| format!("failed to open log file at {}: {e}", log_file.display()))?;

    let file_size = file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("failed to seek log file: {e}"))?;

    let read_from = if file_size > TAIL_BYTES {
        file_size - TAIL_BYTES
    } else {
        0
    };

    file.seek(SeekFrom::Start(read_from))
        .map_err(|e| format!("failed to seek log file: {e}"))?;

    let mut buf = Vec::with_capacity((file_size - read_from) as usize + 1);
    file.read_to_end(&mut buf)
        .map_err(|e| format!("failed to read log file: {e}"))?;

    let text = String::from_utf8_lossy(&buf);

    // If we seeked into the middle of the file, skip the first (likely partial) line.
    let content = if read_from > 0 {
        match text.find('\n') {
            Some(pos) => &text[pos + 1..],
            None => &text,
        }
    } else {
        &text
    };

    let lines: Vec<String> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();

    // Return the last MAX_LINES lines
    let start = if lines.len() > MAX_LINES {
        lines.len() - MAX_LINES
    } else {
        0
    };
    Ok(lines[start..].to_vec())
}

#[tauri::command]
fn get_agent_status() -> Value {
    let running = Command::new("pgrep")
        .args(["-x", "core-agent"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    json!({
        "running": running,
        "simulation_mode": read_simulation_mode_inner(),
    })
}

fn read_simulation_mode_inner() -> bool {
    let Ok(path) = config_file_path() else {
        return true;
    };
    if !path.exists() {
        return true;
    }
    let Ok(contents) = fs::read_to_string(&path) else {
        return true;
    };
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("simulation_mode") {
            let val = rest.trim().trim_start_matches('=').trim();
            return val.starts_with("true");
        }
    }
    true
}

#[tauri::command]
fn get_simulation_mode() -> bool {
    read_simulation_mode_inner()
}

#[tauri::command]
fn set_simulation_mode(enabled: bool) -> Result<(), String> {
    let path = config_file_path()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create runtime dir: {e}"))?;
    }

    let existing = if path.exists() {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };

    let new_line = format!("simulation_mode = {enabled}");
    let updated = if existing.lines().any(|l| l.trim().starts_with("simulation_mode")) {
        existing
            .lines()
            .map(|l| {
                if l.trim().starts_with("simulation_mode") {
                    new_line.as_str()
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else if existing.trim().is_empty() {
        new_line
    } else {
        format!("{}\n{}", existing.trim_end(), new_line)
    };

    fs::write(&path, updated).map_err(|e| format!("failed to write config: {e}"))
}

#[tauri::command]
fn get_acknowledged_incidents() -> Result<Vec<String>, String> {
    let path = ack_file_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read acknowledged incidents: {e}"))?;
    Ok(serde_json::from_str::<Vec<String>>(&contents).unwrap_or_default())
}

#[tauri::command]
fn acknowledge_incident(incident_id: String) -> Result<(), String> {
    do_acknowledge_incident(&incident_id)
}

#[tauri::command]
fn quarantine_file(file_path: String) -> Result<(), String> {
    let root = project_root()?;
    let quarantine_dir = root.join("runtime").join("quarantine");

    fs::create_dir_all(&quarantine_dir)
        .map_err(|e| format!("failed to create quarantine dir: {e}"))?;

    let source = PathBuf::from(&file_path);
    if !source.exists() {
        return Err(format!("file not found: {file_path}"));
    }

    let filename = source
        .file_name()
        .ok_or_else(|| "invalid file path".to_string())?;

    let dest = quarantine_dir.join(filename);
    fs::rename(&source, &dest).map_err(|e| format!("failed to quarantine file: {e}"))
}

// ── Whitelist ─────────────────────────────────────────────────────────────────

fn read_whitelist_inner(path: &std::path::PathBuf) -> (Vec<String>, Vec<String>, Vec<String>) {
    let contents = if path.exists() {
        fs::read_to_string(path).unwrap_or_default()
    } else {
        String::new()
    };
    let mut in_whitelist = false;
    let mut section_lines: Vec<&str> = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if trimmed == "[whitelist]" {
                in_whitelist = true;
                continue;
            } else if in_whitelist {
                break;
            }
        }
        if in_whitelist {
            section_lines.push(line);
        }
    }
    let section = section_lines.join("\n");
    (
        parse_toml_str_array(&section, "trusted_process_paths"),
        parse_toml_str_array(&section, "trusted_process_names"),
        parse_toml_str_array(&section, "trusted_app_bundle_paths"),
    )
}

fn parse_toml_str_array(section: &str, key: &str) -> Vec<String> {
    let key_eq = format!("{key} =");
    let pos = match section.find(&key_eq) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let after_key = &section[pos + key_eq.len()..];
    let bracket_open = match after_key.find('[') {
        Some(p) => p,
        None => return Vec::new(),
    };
    let after_bracket = &after_key[bracket_open + 1..];
    let bracket_close = match after_bracket.find(']') {
        Some(p) => p,
        None => return Vec::new(),
    };
    let array_content = &after_bracket[..bracket_close];
    let mut result = Vec::new();
    let mut rest = array_content;
    while let Some(open_q) = rest.find('"') {
        rest = &rest[open_q + 1..];
        if let Some(close_q) = rest.find('"') {
            let val = &rest[..close_q];
            if !val.is_empty() {
                result.push(val.to_string());
            }
            rest = &rest[close_q + 1..];
        } else {
            break;
        }
    }
    result
}

fn strip_whitelist_section(content: &str) -> String {
    let mut result_lines: Vec<&str> = Vec::new();
    let mut in_whitelist = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if trimmed == "[whitelist]" {
                in_whitelist = true;
                continue;
            } else {
                in_whitelist = false;
            }
        }
        if !in_whitelist {
            result_lines.push(line);
        }
    }
    result_lines.join("\n")
}

fn format_whitelist_section(paths: &[String], names: &[String], bundles: &[String]) -> String {
    let fmt_array = |items: &[String]| -> String {
        if items.is_empty() {
            return "[]".to_string();
        }
        let entries: Vec<String> = items.iter().map(|s| format!("  \"{s}\"")).collect();
        format!("[\n{}\n]", entries.join(",\n"))
    };
    format!(
        "[whitelist]\ntrusted_process_paths = {}\ntrusted_process_names = {}\ntrusted_app_bundle_paths = {}",
        fmt_array(paths),
        fmt_array(names),
        fmt_array(bundles),
    )
}

#[tauri::command]
fn get_whitelist() -> Result<Value, String> {
    let path = config_file_path()?;
    let (paths, names, bundles) = read_whitelist_inner(&path);
    Ok(json!({
        "trusted_process_paths": paths,
        "trusted_process_names": names,
        "trusted_app_bundle_paths": bundles,
    }))
}

#[tauri::command]
fn update_whitelist(
    trusted_process_paths: Vec<String>,
    trusted_process_names: Vec<String>,
    trusted_app_bundle_paths: Vec<String>,
) -> Result<(), String> {
    let path = config_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create runtime dir: {e}"))?;
    }
    let existing = if path.exists() {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };
    let without_whitelist = strip_whitelist_section(&existing);
    let new_section = format_whitelist_section(
        &trusted_process_paths,
        &trusted_process_names,
        &trusted_app_bundle_paths,
    );
    let base = without_whitelist.trim_end();
    let new_content = if base.is_empty() {
        new_section
    } else {
        format!("{base}\n\n{new_section}")
    };
    fs::write(&path, new_content).map_err(|e| format!("failed to write config: {e}"))
}

// ── AI explanation ───────────────────────────────────────────────────────────

const KEYCHAIN_SERVICE: &str = "com.hound.app";
const KEYCHAIN_ACCOUNT: &str = "anthropic_api_key";

fn read_api_key_inner() -> Option<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).ok()?;
    match entry.get_password() {
        Ok(key) if !key.trim().is_empty() => Some(key.trim().to_string()),
        _ => None,
    }
}

#[tauri::command]
fn get_ai_configured() -> bool {
    read_api_key_inner().is_some()
}

#[tauri::command]
fn set_api_key(key: String) -> Result<(), String> {
    let trimmed = key.trim().to_string();
    if trimmed.is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("keychain error: {e}"))?;
    entry
        .set_password(&trimmed)
        .map_err(|e| format!("failed to save to keychain: {e}"))
}

#[tauri::command]
async fn explain_incident(incident_json: String) -> Result<String, String> {
    let api_key = read_api_key_inner()
        .ok_or_else(|| "Anthropic API key not configured. Add it in Settings.".to_string())?;

    // Parse the incident to extract key fields for the prompt
    let incident: Value = serde_json::from_str(&incident_json)
        .map_err(|e| format!("failed to parse incident: {e}"))?;

    let severity = incident.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown");
    let score = incident.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
    let confidence = incident.get("confidence").and_then(|v| v.as_str()).unwrap_or("unknown");
    let attack_chain = incident.get("attack_chain_label").and_then(|v| v.as_str()).unwrap_or("");
    let reason = incident.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let primary_path = incident.get("primary_path").and_then(|v| v.as_str()).unwrap_or("none");
    let process_name = incident.get("process_name").and_then(|v| v.as_str()).unwrap_or("none");
    let mitre_techniques = incident
        .get("mitre_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let signals = incident
        .get("supporting_events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let timeline = incident
        .get("timeline_steps")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .enumerate()
                .map(|(i, s)| format!("{}. {}", i + 1, s))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    let prompt = format!(
        r#"You are an endpoint security analyst explaining a macOS security incident to a non-technical user.

Incident details:
- Severity: {severity} (score: {score}/100, confidence: {confidence})
- Summary: {attack_chain}
- Detection reason: {reason}
- Affected process: {process_name}
- Affected path: {primary_path}
- MITRE ATT&CK techniques: {mitre_techniques}
- Detection signals: {signals}
- Attack chain timeline:
{timeline}

Write a plain-English explanation in 3 short paragraphs:
1. What happened (what the system detected, in simple terms)
2. Why it's concerning (what an attacker could be trying to do)
3. What the user should do (concrete next steps)

Be direct and clear. Avoid jargon. Do not repeat the raw technical terms — translate them. Do not use bullet points."#
    );

    let body = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 512,
        "messages": [{"role": "user", "content": prompt}]
    });

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("API error {status}: {text}"));
    }

    let resp_json: Value = response
        .json()
        .await
        .map_err(|e| format!("failed to parse API response: {e}"))?;

    let explanation = resp_json
        .get("content")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|block| block.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "unexpected API response structure".to_string())?;

    Ok(explanation.to_string())
}

// ── HoundTrace ─────────────────────────────────────────────────────────────────

fn hound_traces_file_path() -> Result<PathBuf, String> {
    Ok(project_root()?
        .join("runtime")
        .join("logs")
        .join("hound_traces.jsonl"))
}

fn ack_v2_file_path() -> Result<PathBuf, String> {
    Ok(project_root()?
        .join("runtime")
        .join("acknowledged-incidents-v2.json"))
}

fn unack_incidents_file_path() -> Result<PathBuf, String> {
    Ok(project_root()?
        .join("runtime")
        .join("unacknowledged-incidents.json"))
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct HoundTrace {
    incident_id: String,
    timestamp: String,
    headline: String,
    what_happened: String,
    what_was_targeted: String,
    how_it_was_caught: String,
    what_we_did: String,
    risk_level: String,
    mitre_summary: String,
    verdict: String,
    ai_enhanced: bool,
}

fn generate_hound_trace_from_incident(incident: &Value, simulation_mode: bool) -> HoundTrace {
    let incident_id = incident.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let severity = incident.get("severity").and_then(|v| v.as_str()).unwrap_or("medium");
    let confidence = incident.get("confidence").and_then(|v| v.as_str()).unwrap_or("medium");
    let attack_chain = incident.get("attack_chain_label").and_then(|v| v.as_str()).unwrap_or("generic_behavioral_incident");
    let process_name = incident.get("process_name").and_then(|v| v.as_str()).unwrap_or("an unknown process");
    let primary_path = incident.get("primary_path").and_then(|v| v.as_str()).unwrap_or("an unknown path");
    let filename = primary_path.split('/').last().unwrap_or(primary_path);
    let score = incident.get("score").and_then(|v| v.as_u64()).unwrap_or(0);

    let supporting_events: Vec<&str> = incident.get("supporting_events")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let signal_count = supporting_events.len();

    let mitre_techniques: Vec<&str> = incident.get("mitre_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let signals_readable: Vec<String> = supporting_events.iter()
        .map(|e| e.replace("alert_", "").replace('_', " "))
        .collect();
    let signals_joined = signals_readable.join(", ");

    // Verdict determination
    let verdict = if simulation_mode {
        "Simulated block"
    } else if score >= 85 {
        "Blocked"
    } else {
        "Monitoring"
    };

    let risk_level = match severity {
        "critical" => "Critical",
        "high"     => "High",
        "medium"   => "Medium",
        "low"      => "Low",
        _          => "Medium",
    };

    let mitre_summary = if mitre_techniques.is_empty() {
        "No specific MITRE ATT&CK techniques were mapped to this incident.".to_string()
    } else {
        format!(
            "This activity maps to {} — techniques documented in the MITRE ATT&CK framework as commonly used in targeted attacks against macOS systems.",
            mitre_techniques.join(", ")
        )
    };

    // Template selection
    let (headline, what_happened, what_was_targeted, how_it_was_caught) = match attack_chain {
        "download_and_execute" => (
            format!("A file downloaded from the internet tried to run on your Mac"),
            format!(
                "A file called '{}' was downloaded to your Mac, made executable, and launched — following \
                 the exact sequence used by malware installers. macOS had flagged it with a quarantine \
                 attribute indicating it came from the internet, but execution proceeded anyway. This pattern \
                 matches the delivery stage of a dropper attack, where an initial file installs additional \
                 malicious software once it runs.",
                filename
            ),
            format!(
                "The file '{}' was the delivery vehicle. The process '{}' was responsible for launching it.",
                primary_path, process_name
            ),
            format!(
                "{} behavioral signals fired in sequence: the file carried a quarantine flag from the \
                 internet, its permissions were changed to executable, then it launched from your Downloads \
                 folder. Each signal alone is low-risk, but this specific sequence has {}-confidence \
                 correlation with malware delivery chains.",
                signal_count, confidence
            ),
        ),
        "curl_pipe_bash" => (
            format!("A process tried to download and immediately execute code from the internet"),
            format!(
                "The process '{}' attempted a curl-pipe-bash attack — one of the most dangerous command \
                 patterns on macOS. It downloads a script directly from the internet and pipes it straight \
                 into a shell interpreter without ever writing a file to disk, bypassing many file-based \
                 security checks. Attackers use this to silently install backdoors or steal data in a \
                 single command that leaves almost no trace.",
                process_name
            ),
            format!(
                "Process '{}' initiated the attack from '{}'.",
                process_name, primary_path
            ),
            format!(
                "The command pattern engine detected a pipe-to-shell sequence ({} signals matched). \
                 curl-pipe-bash is explicitly flagged as a critical LOLBin execution pattern. The {} \
                 confidence score reflects both the unambiguous pattern match and the surrounding \
                 behavioral context.",
                signal_count, confidence
            ),
        ),
        "persistence_installation" => (
            format!("Something attempted to install itself to run automatically at startup"),
            format!(
                "A process named '{}' wrote to a Launch Agent or Launch Daemon location — the mechanism \
                 macOS uses to start programs automatically at login or boot. This is a classic persistence \
                 technique: once installed, the software re-runs every time your Mac starts, surviving \
                 reboots and making removal much harder. Legitimate software sometimes installs agents this \
                 way, but the surrounding behavioral context raised flags.",
                process_name
            ),
            format!(
                "The persistence target was '{}'. The process '{}' performed the installation.",
                primary_path, process_name
            ),
            format!(
                "{} signals pointed to persistence activity: persistence tooling execution, a plist write \
                 to a monitored directory, and the suspicious process context. The path '{}' is a known \
                 persistence location on macOS.",
                signal_count, filename
            ),
        ),
        "credential_theft" => (
            format!("A process tried to access your saved passwords or credentials"),
            format!(
                "The process '{}' attempted to access credential storage — targeting either the macOS \
                 Keychain, browser password databases, or SSH private keys. This is among the highest-value \
                 targets for attackers: successful credential theft can give them access to email, bank \
                 accounts, cloud services, and work systems without needing to break any passwords.",
                process_name
            ),
            format!(
                "Process '{}' targeted credentials at or near '{}'.",
                process_name, primary_path
            ),
            format!(
                "{} credential-access signals fired: {}. These patterns specifically match known macOS \
                 credential harvesting techniques used in post-compromise attacks.",
                signal_count, signals_joined
            ),
        ),
        "ransomware_attack" => (
            format!("Activity consistent with ransomware was detected on your Mac"),
            format!(
                "Hound detected a burst of file modification activity matching ransomware behavior: \
                 rapid writes across multiple files, possible extension changes, and content patterns that \
                 suggest encryption in progress. Process '{}' was at the center of this activity. \
                 Ransomware encrypts your files and demands payment for the decryption key — early detection \
                 is critical to limiting damage.",
                process_name
            ),
            format!(
                "Process '{}' was modifying files in the area of '{}'.",
                process_name, primary_path
            ),
            format!(
                "The ransomware heuristics engine flagged {} signals: burst file activity, a possible \
                 file rename wave, and high-entropy write patterns. This combination at {} confidence \
                 triggered an automatic response.",
                signal_count, confidence
            ),
        ),
        "recon_chain" => (
            format!("A process was mapping out your system before a potential attack"),
            format!(
                "The process '{}' ran a sequence of system discovery commands — querying your hardware \
                 profile, network configuration, installed software, and running processes. \
                 Reconnaissance like this is typically a precursor to a more targeted attack: attackers \
                 map the environment to identify valuable targets, understand your defenses, and plan \
                 their next move with precision.",
                process_name
            ),
            format!(
                "Process '{}' conducted discovery from '{}'.",
                process_name, primary_path
            ),
            format!(
                "{} discovery signals were detected: {}. \
                 Legitimate software rarely needs to query all of these system properties in rapid succession.",
                signal_count, signals_joined
            ),
        ),
        "staging_and_exfil" => (
            format!("A process may have been preparing your files for theft"),
            format!(
                "Process '{}' was observed copying or archiving files to a staging location — behavior \
                 associated with data exfiltration. Attackers typically aggregate the files they want to \
                 steal into a single location before transmitting them. The combination of rapid file \
                 access, archive creation, and outbound network activity is a strong signal that data \
                 theft may be in progress.",
                process_name
            ),
            format!(
                "Process '{}' was staging data near '{}'. ",
                process_name, primary_path
            ),
            format!(
                "{} signals detected: data staging activity, archive creation, and suspicious outbound \
                 network connections. The {} confidence reflects the multi-signal correlation across \
                 file and network events.",
                signal_count, confidence
            ),
        ),
        "lateral_movement_chain" => (
            format!("A process attempted to reach other systems on your network"),
            format!(
                "Hound detected lateral movement patterns from process '{}' — attempts to connect \
                 to other systems using SSH, file transfer tools, or remote execution protocols. Lateral \
                 movement is how attackers spread through a network after gaining an initial foothold, \
                 pivoting from machine to machine until they reach their real target.",
                process_name
            ),
            format!(
                "Process '{}' initiated connections from '{}'.",
                process_name, primary_path
            ),
            format!(
                "{} lateral movement signals detected: SSH invocations, network tool use, or remote \
                 connection attempts. The originating path '{}' is unusual for legitimate remote access tools.",
                signal_count, filename
            ),
        ),
        "masquerading" => (
            format!("A process was pretending to be a trusted macOS application"),
            format!(
                "The process at '{}' was detected impersonating a legitimate macOS system process or \
                 application. Masquerading is a defense-evasion technique where malware names itself after \
                 trusted software — Finder, Safari, system daemons — hoping to blend in and avoid scrutiny. \
                 The mismatch between the claimed process identity and its actual location on disk gave it away.",
                primary_path
            ),
            format!(
                "Process '{}' was impersonating a trusted identity from '{}'.",
                process_name, primary_path
            ),
            format!(
                "The masquerading detector found a mismatch between the claimed process name and its \
                 actual binary location. {} additional signals confirmed the suspicious behavioral context.",
                signal_count
            ),
        ),
        "indicator_removal" => (
            format!("A process tried to cover its tracks by erasing evidence"),
            format!(
                "Process '{}' attempted to delete or modify logs, command history, or other forensic \
                 indicators. This is a classic anti-forensics technique: attackers erase evidence of their \
                 presence to delay detection and complicate investigation. The deletion of \
                 security-relevant records is itself one of the strongest indicators of a compromised system.",
                process_name
            ),
            format!(
                "Process '{}' targeted forensic evidence near '{}'.",
                process_name, primary_path
            ),
            format!(
                "{} indicator removal signals fired: {}. These patterns specifically match known macOS \
                 anti-forensics and log-clearing techniques.",
                signal_count, signals_joined
            ),
        ),
        "privilege_escalation_attempt" => (
            format!("A process tried to gain administrator access on your Mac"),
            format!(
                "The process '{}' attempted to escalate its privileges — moving from a limited user account \
                 toward administrator or root access. Privilege escalation is a critical step in most attacks: \
                 with elevated permissions, attackers can access protected files, install software \
                 system-wide, disable security tools, and create persistent access that survives reboots.",
                process_name
            ),
            format!(
                "Process '{}' attempted privilege escalation from '{}'.",
                process_name, primary_path
            ),
            format!(
                "{} privilege escalation signals detected: sudo invocations, authorization prompts, \
                 setuid/setgid file operations, or user account manipulation. The {} confidence \
                 reflects the clarity of the escalation attempt.",
                signal_count, confidence
            ),
        ),
        "lolbin_to_persistence" => (
            format!("A built-in macOS tool was abused to install persistent access"),
            format!(
                "A legitimate macOS system binary ('{}') was used in an unusual way to achieve persistence — \
                 ensuring attacker-controlled code will run automatically on future startups. This technique, \
                 known as 'living off the land', uses trusted built-in tools to avoid triggering \
                 signature-based security. Using a trusted binary to install a backdoor is a hallmark of \
                 sophisticated, targeted attacks.",
                process_name
            ),
            format!(
                "The system tool '{}' modified the persistence target '{}'.",
                process_name, primary_path
            ),
            format!(
                "{} signals identified: LOLBin execution (a trusted tool used offensively), followed by \
                 a persistence installation action. The {} confidence score reflects both the tool-abuse \
                 pattern and the resulting system modification.",
                signal_count, confidence
            ),
        ),
        _ => (
            format!("Suspicious behavioral activity was detected on your Mac"),
            format!(
                "Hound detected a combination of {} behavioral signals from process '{}' that \
                 together indicate potentially malicious activity. While no single signal was conclusive, \
                 the combination and timing of these events — occurring within a short window — raises the \
                 overall risk to {}. This kind of multi-signal correlation is how sophisticated attacks are \
                 distinguished from normal system activity.",
                signal_count, process_name, severity
            ),
            format!(
                "Process '{}' was active near '{}'.",
                process_name, primary_path
            ),
            format!(
                "{} behavioral signals were correlated: {}. The incident engine grouped these based on \
                 process identity, file path proximity, and timing — all occurring within the detection window.",
                signal_count, signals_joined
            ),
        ),
    };

    let what_we_did = match verdict {
        "Blocked" => format!(
            "Hound took immediate action: the process was terminated and '{}' was moved to \
             quarantine. These actions stop the attack chain from continuing. Review the incident to \
             confirm you recognize the file — if it was legitimate, you can restore it from quarantine.",
            filename
        ),
        "Simulated block" => format!(
            "Hound is running in simulation mode. If live response were enabled, the process \
             would have been terminated and '{}' moved to quarantine. No automatic action was taken. \
             You can manually quarantine the file from this screen, or enable live response in Settings.",
            filename
        ),
        _ => format!(
            "Hound is monitoring this threat. The behavioral pattern is being tracked but no \
             automatic action threshold was reached. Review the details carefully — if this activity \
             is unexpected, consider manually quarantining '{}' and checking the process.",
            filename
        ),
    };

    HoundTrace {
        incident_id,
        timestamp,
        headline,
        what_happened,
        what_was_targeted,
        how_it_was_caught,
        what_we_did,
        risk_level: risk_level.to_string(),
        mitre_summary,
        verdict: verdict.to_string(),
        ai_enhanced: false,
    }
}

fn save_hound_trace_inner(trace: &HoundTrace) -> Result<(), String> {
    let path = hound_traces_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create dir: {e}"))?;
    }
    let line = serde_json::to_string(trace).map_err(|e| format!("serialize error: {e}"))?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("failed to open hound_traces file: {e}"))?;
    writeln!(file, "{}", line).map_err(|e| format!("failed to write hound_trace: {e}"))
}

fn do_acknowledge_incident(incident_id: &str) -> Result<(), String> {
    let path = ack_file_path()?;
    let mut ids: Vec<String> = if path.exists() {
        let contents = fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        vec![]
    };
    if !ids.contains(&incident_id.to_string()) {
        ids.push(incident_id.to_string());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create runtime dir: {e}"))?;
    }
    let serialized = serde_json::to_string(&ids).map_err(|e| format!("failed to serialize: {e}"))?;
    fs::write(&path, serialized).map_err(|e| format!("failed to write: {e}"))
}

fn append_ack_v2(incident_id: &str, resolved_reason: &str) -> Result<(), String> {
    let path = ack_v2_file_path()?;
    let mut records: Vec<Value> = if path.exists() {
        let contents = fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        vec![]
    };
    // Upsert — don't duplicate
    if !records.iter().any(|r| r.get("id").and_then(|v| v.as_str()) == Some(incident_id)) {
        records.push(json!({
            "id": incident_id,
            "resolved_reason": resolved_reason,
            "resolved_at": chrono::Utc::now().to_rfc3339(),
        }));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create dir: {e}"))?;
    }
    let serialized = serde_json::to_string(&records).map_err(|e| format!("serialize error: {e}"))?;
    fs::write(&path, serialized).map_err(|e| format!("failed to write ack v2: {e}"))
}

#[tauri::command]
fn generate_hound_trace(incident_json: String) -> Result<Value, String> {
    let incident: Value = serde_json::from_str(&incident_json)
        .map_err(|e| format!("failed to parse incident: {e}"))?;
    let sim_mode = read_simulation_mode_inner();
    let hound_trace = generate_hound_trace_from_incident(&incident, sim_mode);
    serde_json::to_value(&hound_trace).map_err(|e| format!("failed to serialize hound_trace: {e}"))
}

#[tauri::command]
fn acknowledge_with_hound_trace(
    incident_json: String,
    resolved_reason: String,
) -> Result<Value, String> {
    let incident: Value = serde_json::from_str(&incident_json)
        .map_err(|e| format!("failed to parse incident: {e}"))?;

    let incident_id = incident.get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "incident missing id field".to_string())?
        .to_string();

    // 1. Acknowledge in old format (backward compat)
    do_acknowledge_incident(&incident_id)?;

    // 2. Write v2 ack record with resolved_reason
    append_ack_v2(&incident_id, &resolved_reason)?;

    // 3. Remove from unacknowledged persistence (state transition: Inbox → Resolved)
    let _ = remove_unacknowledged_incident_inner(&incident_id);

    // 4. Generate Hound Trace
    let sim_mode = read_simulation_mode_inner();
    let hound_trace = generate_hound_trace_from_incident(&incident, sim_mode);

    // 5. Persist Hound Trace to hound_traces.jsonl
    save_hound_trace_inner(&hound_trace)?;

    // 6. Return the Hound Trace
    serde_json::to_value(&hound_trace).map_err(|e| format!("failed to serialize: {e}"))
}

#[tauri::command]
fn get_hound_traces() -> Result<Vec<Value>, String> {
    let path = hound_traces_file_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read hound_traces: {e}"))?;
    let mut result: Vec<Value> = contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    result.reverse(); // newest first
    Ok(result)
}

#[tauri::command]
fn get_acknowledged_records() -> Result<Vec<Value>, String> {
    let path = ack_v2_file_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read acknowledged records: {e}"))?;
    let records: Vec<Value> = serde_json::from_str(&contents).unwrap_or_default();
    Ok(records)
}

// ── Unacknowledged incident persistence ──────────────────────────────────────

/// Upsert a single TelemetryEvent (alert_behavioral_incident) by its id.
#[tauri::command]
fn save_unacknowledged_incident(event_json: String) -> Result<(), String> {
    let path = unack_incidents_file_path()?;
    let new_event: Value = serde_json::from_str(&event_json)
        .map_err(|e| format!("failed to parse event: {e}"))?;
    let event_id = new_event
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "event missing id field".to_string())?
        .to_string();

    let mut events: Vec<Value> = if path.exists() {
        let contents = fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        vec![]
    };

    if !events
        .iter()
        .any(|e| e.get("id").and_then(|v| v.as_str()) == Some(&event_id))
    {
        events.push(new_event);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create dir: {e}"))?;
    }
    let serialized =
        serde_json::to_string(&events).map_err(|e| format!("failed to serialize: {e}"))?;
    fs::write(&path, serialized).map_err(|e| format!("failed to write: {e}"))
}

/// Bulk upsert — used on initial load to sync events from the log file into the
/// persistence file so they survive the 1MB log tail window across restarts.
#[tauri::command]
fn sync_unacknowledged_incidents(event_jsons: Vec<String>) -> Result<(), String> {
    let path = unack_incidents_file_path()?;
    let mut existing: Vec<Value> = if path.exists() {
        let contents = fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        vec![]
    };

    let existing_ids: std::collections::HashSet<String> = existing
        .iter()
        .filter_map(|e| e.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();

    for json_str in event_jsons {
        let Ok(event) = serde_json::from_str::<Value>(&json_str) else {
            continue;
        };
        let Some(id) = event.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if !existing_ids.contains(id) {
            existing.push(event);
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create dir: {e}"))?;
    }
    let serialized =
        serde_json::to_string(&existing).map_err(|e| format!("failed to serialize: {e}"))?;
    fs::write(&path, serialized).map_err(|e| format!("failed to write: {e}"))
}

/// Return all persisted unacknowledged incident events.
#[tauri::command]
fn get_unacknowledged_incidents() -> Result<Vec<Value>, String> {
    let path = unack_incidents_file_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read unacknowledged incidents: {e}"))?;
    Ok(serde_json::from_str(&contents).unwrap_or_default())
}

/// Remove a single incident event from the persistence file by its event id.
/// Called internally when an incident is acknowledged.
fn remove_unacknowledged_incident_inner(incident_id: &str) -> Result<(), String> {
    let path = unack_incidents_file_path()?;
    if !path.exists() {
        return Ok(());
    }
    let contents = fs::read_to_string(&path).unwrap_or_default();
    let mut events: Vec<Value> = serde_json::from_str(&contents).unwrap_or_default();
    let before = events.len();
    events.retain(|e| e.get("id").and_then(|v| v.as_str()) != Some(incident_id));
    if events.len() != before {
        let serialized =
            serde_json::to_string(&events).map_err(|e| format!("failed to serialize: {e}"))?;
        fs::write(&path, serialized).map_err(|e| format!("failed to write: {e}"))?;
    }
    Ok(())
}

// ── Onboarding ───────────────────────────────────────────────────────────────

#[tauri::command]
fn is_first_run() -> Result<bool, String> {
    let path = config_file_path()?;
    if !path.exists() {
        return Ok(true);
    }
    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read config: {e}"))?;
    let found = contents
        .lines()
        .any(|l| l.trim().starts_with("first_run_complete"));
    Ok(!found)
}

#[tauri::command]
fn complete_onboarding() -> Result<(), String> {
    let path = config_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create runtime dir: {e}"))?;
    }
    let existing = if path.exists() {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };
    let new_line = "first_run_complete = true";
    let updated = if existing
        .lines()
        .any(|l| l.trim().starts_with("first_run_complete"))
    {
        existing
            .lines()
            .map(|l| {
                if l.trim().starts_with("first_run_complete") {
                    new_line
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else if existing.trim().is_empty() {
        new_line.to_string()
    } else {
        format!("{}\n{}", existing.trim_end(), new_line)
    };
    fs::write(&path, updated).map_err(|e| format!("failed to write config: {e}"))
}

#[derive(serde::Serialize)]
struct PermissionStatus {
    full_disk_access: bool,
    accessibility: bool,
}

#[tauri::command]
fn check_permissions() -> PermissionStatus {
    // Full Disk Access: try opening TCC-protected files. On macOS 15 the
    // system-level TCC.db is SIP-protected even with FDA; use the user-level
    // database and Safari history as more reliable indicators.
    let home = std::env::var("HOME").unwrap_or_default();
    let fda_candidates = [
        format!("{home}/Library/Application Support/com.apple.TCC/TCC.db"),
        format!("{home}/Library/Safari/History.db"),
        "/Library/Application Support/com.apple.TCC/TCC.db".to_string(),
    ];
    let full_disk_access = fda_candidates
        .iter()
        .any(|path| std::fs::File::open(path).is_ok());

    // Accessibility: ask System Events via osascript — succeeds only if granted.
    let accessibility = Command::new("osascript")
        .args(["-e", "tell application \"System Events\" to return true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    PermissionStatus {
        full_disk_access,
        accessibility,
    }
}

// ── Auth token ────────────────────────────────────────────────────────────────

const KEYCHAIN_AUTH_ACCOUNT: &str = "auth_token";

#[tauri::command]
fn get_auth_token() -> Option<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_AUTH_ACCOUNT).ok()?;
    match entry.get_password() {
        Ok(token) if !token.trim().is_empty() => Some(token.trim().to_string()),
        _ => None,
    }
}

#[tauri::command]
fn save_auth_token(token: String) -> Result<(), String> {
    let trimmed = token.trim().to_string();
    if trimmed.is_empty() {
        return Err("token cannot be empty".to_string());
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_AUTH_ACCOUNT)
        .map_err(|e| format!("keychain error: {e}"))?;
    entry
        .set_password(&trimmed)
        .map_err(|e| format!("failed to save auth token: {e}"))
}

#[tauri::command]
fn sign_out() -> Result<(), String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_AUTH_ACCOUNT)
        .map_err(|e| format!("keychain error: {e}"))?;
    entry
        .delete_credential()
        .map_err(|e| format!("failed to clear auth token: {e}"))
}

// ── Agent identity ────────────────────────────────────────────────────────────

/// Return a stable agent ID, generating and persisting one if absent.
///
/// The ID is stored in `runtime/agent-config.toml` under `[agent]` as `id = "..."`.
/// This gives each Hound installation a unique, stable identifier for telemetry.
#[tauri::command]
fn get_agent_id() -> String {
    let Ok(config_path) = config_file_path() else {
        return uuid::Uuid::new_v4().to_string();
    };

    // Read the existing config
    let contents = fs::read_to_string(&config_path).unwrap_or_default();

    // Try to find an existing [agent] id = "..."
    let mut in_agent_section = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[agent]" {
            in_agent_section = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_agent_section = false;
        }
        if in_agent_section {
            if let Some(rest) = trimmed.strip_prefix("id") {
                let val = rest.trim().trim_start_matches('=').trim().trim_matches('"');
                if !val.is_empty() {
                    return val.to_string();
                }
            }
        }
    }

    // No ID found — generate one and append to config
    let new_id = uuid::Uuid::new_v4().to_string();
    let agent_section = format!("\n[agent]\nid = \"{new_id}\"\n");
    let mut updated = contents;
    updated.push_str(&agent_section);
    let _ = fs::write(&config_path, &updated);
    new_id
}

/// Return the macOS version string (e.g. "15.4.1") from `sw_vers`.
#[tauri::command]
fn get_macos_version() -> String {
    Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

// ── False positive cleanup ────────────────────────────────────────────────────

/// Remove incidents from unacknowledged-incidents.json that were generated by
/// processes on the detection whitelist (trusted dev tools: cargo, ZoomUpdater, etc.).
/// Returns the count of removed incidents.
#[tauri::command]
fn clear_false_positives() -> Result<usize, String> {
    let incidents_path = project_root()?.join("runtime").join("unacknowledged-incidents.json");

    if !incidents_path.exists() {
        return Ok(0);
    }

    let raw = fs::read_to_string(&incidents_path)
        .map_err(|e| format!("failed to read unacknowledged incidents: {e}"))?;

    let incidents: Vec<serde_json::Value> = serde_json::from_str(&raw)
        .map_err(|e| format!("failed to parse unacknowledged incidents: {e}"))?;

    // Read the detection whitelist from config
    let config_path = config_file_path()?;
    let config_raw = fs::read_to_string(&config_path).unwrap_or_default();
    let suppressed_names = parse_detection_whitelist_names(&config_raw);
    let suppressed_prefixes = parse_detection_whitelist_prefixes(&config_raw);

    let before = incidents.len();

    let kept: Vec<serde_json::Value> = incidents
        .into_iter()
        .filter(|inc| {
            // Extract the chosen_command and primary_path from the incident payload
            let details = inc
                .get("payload")
                .and_then(|p| p.get("details"));

            let command = details
                .and_then(|d| d.get("chosen_command"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let path = details
                .and_then(|d| d.get("primary_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Keep this incident unless its command/path is on the detection whitelist
            !is_suppressed_fp(command, path, &suppressed_names, &suppressed_prefixes)
        })
        .collect();

    let removed = before - kept.len();

    let new_json = serde_json::to_string(&kept)
        .map_err(|e| format!("failed to serialize filtered incidents: {e}"))?;
    fs::write(&incidents_path, new_json)
        .map_err(|e| format!("failed to write cleaned incidents: {e}"))?;

    Ok(removed)
}

fn is_suppressed_fp(
    command: &str,
    path: &str,
    suppressed_names: &[String],
    suppressed_prefixes: &[String],
) -> bool {
    let basename = std::path::Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);

    if suppressed_names.iter().any(|n| n == basename || n == command) {
        return true;
    }
    if !path.is_empty()
        && suppressed_prefixes.iter().any(|p| path.starts_with(p.as_str()))
    {
        return true;
    }
    false
}

fn parse_detection_whitelist_names(config: &str) -> Vec<String> {
    extract_toml_section_body(config, "detection_whitelist")
        .map(|body| parse_toml_string_array_body(&body, "suppressed_process_names"))
        .unwrap_or_default()
}

fn parse_detection_whitelist_prefixes(config: &str) -> Vec<String> {
    extract_toml_section_body(config, "detection_whitelist")
        .map(|body| parse_toml_string_array_body(&body, "suppressed_path_prefixes"))
        .unwrap_or_default()
}

fn extract_toml_section_body(contents: &str, section_name: &str) -> Option<String> {
    let header = format!("[{section_name}]");
    let mut in_section = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if trimmed == header {
                in_section = true;
                continue;
            } else if in_section {
                break;
            }
        }
        if in_section {
            lines.push(line);
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn parse_toml_string_array_body(section: &str, key: &str) -> Vec<String> {
    parse_toml_string_array_body_inner(section, key).unwrap_or_default()
}

fn parse_toml_string_array_body_inner(section: &str, key: &str) -> Option<Vec<String>> {
    let key_eq = format!("{key} =");
    let pos = section.find(&key_eq)?;
    let after_key = &section[pos + key_eq.len()..];
    let bracket_open = after_key.find('[')?;
    let after_bracket = &after_key[bracket_open + 1..];
    let bracket_close = after_bracket.find(']')?;
    let array_content = &after_bracket[..bracket_close];

    let mut result = Vec::new();
    let mut rest = array_content;
    while let Some(open_q) = rest.find('"') {
        rest = &rest[open_q + 1..];
        if let Some(close_q) = rest.find('"') {
            let val = &rest[..close_q];
            if !val.is_empty() {
                result.push(val.to_string());
            }
            rest = &rest[close_q + 1..];
        } else {
            break;
        }
    }
    Some(result)
}

// ── Dark Web Monitor ─────────────────────────────────────────────────────────

const KEYCHAIN_HIBP_ACCOUNT: &str = "hibp_api_key";

/// Path to persistent dark-web monitor state file.
fn dark_web_state_path() -> Result<PathBuf, String> {
    Ok(project_root()?
        .join("runtime")
        .join("dark-web-monitor.json"))
}

fn read_hibp_key() -> Option<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_HIBP_ACCOUNT).ok()?;
    match entry.get_password() {
        Ok(key) if !key.trim().is_empty() => Some(key.trim().to_string()),
        _ => None,
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BreachResult {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breach_date: String,
    pub description: String,
    pub pwn_count: u64,
    pub data_classes: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug)]
struct DarkWebState {
    monitored_emails: Vec<String>,
    /// Map from email → last check ISO timestamp
    last_checked: std::collections::HashMap<String, String>,
    /// Map from email → list of breaches
    breaches: std::collections::HashMap<String, Vec<BreachResult>>,
}

fn load_dark_web_state() -> DarkWebState {
    let path = match dark_web_state_path() {
        Ok(p) => p,
        Err(_) => return DarkWebState::default(),
    };
    if !path.exists() {
        return DarkWebState::default();
    }
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return DarkWebState::default(),
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_dark_web_state(state: &DarkWebState) -> Result<(), String> {
    let path = dark_web_state_path()?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("serialize: {e}"))?;
    fs::write(&path, json).map_err(|e| format!("write: {e}"))
}

#[tauri::command]
fn get_hibp_configured() -> bool {
    read_hibp_key().is_some()
}

#[tauri::command]
fn save_hibp_api_key(key: String) -> Result<(), String> {
    let trimmed = key.trim().to_string();
    if trimmed.is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_HIBP_ACCOUNT)
        .map_err(|e| format!("keychain error: {e}"))?;
    entry
        .set_password(&trimmed)
        .map_err(|e| format!("failed to save HIBP key to keychain: {e}"))
}

#[tauri::command]
fn get_monitored_emails() -> Vec<String> {
    load_dark_web_state().monitored_emails
}

#[tauri::command]
fn save_monitored_email(email: String) -> Result<(), String> {
    let email = email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err("invalid email address".to_string());
    }
    let mut state = load_dark_web_state();
    if !state.monitored_emails.contains(&email) {
        state.monitored_emails.push(email);
    }
    save_dark_web_state(&state)
}

#[tauri::command]
fn remove_monitored_email(email: String) -> Result<(), String> {
    let email = email.trim().to_lowercase();
    let mut state = load_dark_web_state();
    state.monitored_emails.retain(|e| e != &email);
    state.last_checked.remove(&email);
    state.breaches.remove(&email);
    save_dark_web_state(&state)
}

/// Returns cached breaches for all monitored emails.
#[tauri::command]
fn get_breach_results() -> std::collections::HashMap<String, Vec<BreachResult>> {
    load_dark_web_state().breaches
}

/// Returns the last-checked timestamps.
#[tauri::command]
fn get_last_checked() -> std::collections::HashMap<String, String> {
    load_dark_web_state().last_checked
}

/// Check one email against HaveIBeenPwned API v3.
/// Rate limit: 1 req / 1500ms — callers must respect this.
#[tauri::command]
async fn check_email_breaches(email: String) -> Result<Vec<BreachResult>, String> {
    let api_key = read_hibp_key()
        .ok_or_else(|| "HIBP API key not configured. Add it in Dark Web Monitor settings.".to_string())?;

    let email_clean = email.trim().to_lowercase();
    let encoded = urlencoding::encode(&email_clean);
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
        encoded
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("hibp-api-key", &api_key)
        .header("User-Agent", "Hound-EDR/0.1.0")
        .send()
        .await
        .map_err(|e| format!("HIBP request failed: {e}"))?;

    let status = response.status();

    // 404 = email not found in any breach — clean result
    if status == 404 {
        let mut state = load_dark_web_state();
        let now = chrono::Utc::now().to_rfc3339();
        state.last_checked.insert(email_clean.clone(), now);
        state.breaches.insert(email_clean, vec![]);
        let _ = save_dark_web_state(&state);
        return Ok(vec![]);
    }

    if status == 401 {
        return Err("Invalid HIBP API key. Check your key in Dark Web Monitor settings.".to_string());
    }
    if status == 429 {
        return Err("Rate limited by HIBP. Wait a moment and try again.".to_string());
    }
    if !status.is_success() {
        return Err(format!("HIBP API error: HTTP {status}"));
    }

    let raw: Vec<serde_json::Value> = response
        .json()
        .await
        .map_err(|e| format!("failed to parse HIBP response: {e}"))?;

    let breaches: Vec<BreachResult> = raw
        .iter()
        .map(|b| BreachResult {
            name: b["Name"].as_str().unwrap_or("").to_string(),
            title: b["Title"].as_str().unwrap_or("").to_string(),
            domain: b["Domain"].as_str().unwrap_or("").to_string(),
            breach_date: b["BreachDate"].as_str().unwrap_or("").to_string(),
            description: b["Description"].as_str().unwrap_or("").to_string(),
            pwn_count: b["PwnCount"].as_u64().unwrap_or(0),
            data_classes: b["DataClasses"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();

    // Persist results
    let mut state = load_dark_web_state();
    let now = chrono::Utc::now().to_rfc3339();
    state.last_checked.insert(email_clean.clone(), now);
    state.breaches.insert(email_clean, breaches.clone());
    let _ = save_dark_web_state(&state);

    Ok(breaches)
}

// ── File watcher ─────────────────────────────────────────────────────────────

/// Poll the agent log file every 500 ms and emit `agent-events-updated`
/// to the frontend whenever the file size changes.
fn start_log_watcher(app: AppHandle, log_path: PathBuf) {
    eprintln!(
        "[hound] watcher started — polling every 500ms: {}",
        log_path.display()
    );

    std::thread::spawn(move || {
        let mut last_size: u64 = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

        eprintln!(
            "[hound] watcher initial file size: {} bytes",
            last_size
        );

        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));

            let size = match fs::metadata(&log_path) {
                Ok(m) => m.len(),
                Err(e) => {
                    // File may not exist yet (agent hasn't started). Keep waiting.
                    eprintln!(
                        "[hound] watcher: cannot stat {}: {e}",
                        log_path.display()
                    );
                    0
                }
            };

            if size != last_size {
                eprintln!(
                    "[hound] log file changed: {} → {} bytes, emitting agent-events-updated",
                    last_size, size
                );
                last_size = size;
                if let Err(e) = app.emit("agent-events-updated", ()) {
                    eprintln!("[hound] watcher: failed to emit event: {e}");
                }
            }
        }
    });
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // ── Startup diagnostics ───────────────────────────────────────────
            if let Ok(val) = std::env::var("HOUND_ROOT") {
                eprintln!("[hound] HOUND_ROOT={val}");
            }
            match project_root() {
                Ok(root) => {
                    eprintln!("[hound] project root:  {}", root.display());
                }
                Err(e) => {
                    eprintln!("[hound] ERROR resolving project root: {e}");
                }
            }

            let log_path = match ensure_runtime_dirs() {
                Ok(p) => {
                    let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    eprintln!(
                        "[hound] watching log file: {} ({} bytes)",
                        p.display(),
                        size
                    );
                    p
                }
                Err(e) => {
                    eprintln!("[hound] ERROR setting up runtime dirs: {e}");
                    // Fall back to whatever path we can derive, even if the file is missing.
                    log_file_path().unwrap_or_else(|_| PathBuf::from("runtime/logs/agent-events.jsonl"))
                }
            };

            // ── System tray ───────────────────────────────────────────────────
            use tauri::menu::{MenuBuilder, MenuItemBuilder};
            use tauri::tray::{TrayIconBuilder, TrayIconEvent};

            // Hide from Dock — this is a background menu-bar agent.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            if let Some(icon) = app.default_window_icon().cloned() {
                let open_item = MenuItemBuilder::with_id("open", "Open Hound").build(app)?;
                let quit_item = MenuItemBuilder::with_id("quit", "Quit Hound").build(app)?;
                let menu = MenuBuilder::new(app)
                    .items(&[&open_item, &quit_item])
                    .build()?;

                let _ = TrayIconBuilder::new()
                    .icon(icon)
                    .tooltip("Hound — Protected")
                    .menu(&menu)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "open" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            std::process::exit(0);
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if matches!(event, TrayIconEvent::Click { .. }) {
                            let app = tray.app_handle();
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    })
                    .build(app.handle())?;
            }

            start_log_watcher(app.handle().clone(), log_path);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_log_path,
            read_agent_events,
            get_agent_status,
            get_simulation_mode,
            set_simulation_mode,
            get_acknowledged_incidents,
            acknowledge_incident,
            quarantine_file,
            get_ai_configured,
            set_api_key,
            explain_incident,
            get_whitelist,
            update_whitelist,
            generate_hound_trace,
            acknowledge_with_hound_trace,
            get_hound_traces,
            get_acknowledged_records,
            save_unacknowledged_incident,
            sync_unacknowledged_incidents,
            get_unacknowledged_incidents,
            is_first_run,
            complete_onboarding,
            check_permissions,
            get_auth_token,
            save_auth_token,
            sign_out,
            clear_false_positives,
            get_hibp_configured,
            save_hibp_api_key,
            get_monitored_emails,
            save_monitored_email,
            remove_monitored_email,
            get_breach_results,
            get_last_checked,
            check_email_breaches,
            get_agent_id,
            get_macos_version,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
