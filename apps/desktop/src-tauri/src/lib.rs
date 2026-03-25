use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tauri::{AppHandle, Emitter, Manager};

// ── Path helpers ─────────────────────────────────────────────────────────────

/// Resolve the project root at runtime.
///
/// Resolution order:
///   1. `$AGENT_SECURITY_ROOT` env var — explicit override, useful when the
///      app is run from an unexpected working directory.
///   2. `CARGO_MANIFEST_DIR` (baked in at compile time) navigated three
///      levels up: src-tauri → desktop → apps → project-root.
///      This is correct for all `npm run tauri dev` invocations.
///
/// Returns `Err` with a human-readable message if neither strategy works.
fn project_root() -> Result<PathBuf, String> {
    // 1. Explicit environment variable override
    if let Ok(root) = std::env::var("AGENT_SECURITY_ROOT") {
        let path = PathBuf::from(&root);
        if path.is_dir() {
            return Ok(path);
        }
        eprintln!(
            "[agent-security] WARNING: AGENT_SECURITY_ROOT={root} is not a directory, ignoring"
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
             set AGENT_SECURITY_ROOT env var to override",
            path.display()
        ));
    }

    Err("failed to derive project root from CARGO_MANIFEST_DIR — \
         set AGENT_SECURITY_ROOT env var"
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
            "[agent-security] created empty log file: {}",
            log_path.display()
        );
    }

    Ok(log_path)
}

// ── Commands ─────────────────────────────────────────────────────────────────

#[tauri::command]
fn read_agent_events() -> Result<Vec<String>, String> {
    let log_file = log_file_path()?;
    if !log_file.exists() {
        return Ok(vec![]);
    }
    let contents = fs::read_to_string(&log_file)
        .map_err(|e| format!("failed to read log file at {}: {e}", log_file.display()))?;
    Ok(contents.lines().map(|l| l.to_string()).collect())
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
    let path = ack_file_path()?;

    let mut ids: Vec<String> = if path.exists() {
        let contents = fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        vec![]
    };

    if !ids.contains(&incident_id) {
        ids.push(incident_id);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create runtime dir: {e}"))?;
    }

    let serialized =
        serde_json::to_string(&ids).map_err(|e| format!("failed to serialize: {e}"))?;
    fs::write(&path, serialized).map_err(|e| format!("failed to write: {e}"))
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

// ── AI explanation ───────────────────────────────────────────────────────────

fn api_key_config_key() -> &'static str {
    "anthropic_api_key"
}

fn read_api_key_inner() -> Option<String> {
    let path = config_file_path().ok()?;
    let contents = fs::read_to_string(&path).ok()?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(api_key_config_key()) {
            let val = rest.trim().trim_start_matches('=').trim().trim_matches('"').trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

#[tauri::command]
fn get_ai_configured() -> bool {
    read_api_key_inner().is_some()
}

#[tauri::command]
fn set_api_key(key: String) -> Result<(), String> {
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

    let config_key = api_key_config_key();
    let new_line = format!("{config_key} = \"{key}\"");
    let updated = if existing.lines().any(|l| l.trim().starts_with(config_key)) {
        existing
            .lines()
            .map(|l| {
                if l.trim().starts_with(config_key) {
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

// ── File watcher ─────────────────────────────────────────────────────────────

/// Poll the agent log file every 500 ms and emit `agent-events-updated`
/// to the frontend whenever the file size changes.
fn start_log_watcher(app: AppHandle, log_path: PathBuf) {
    eprintln!(
        "[agent-security] watcher started — polling every 500ms: {}",
        log_path.display()
    );

    std::thread::spawn(move || {
        let mut last_size: u64 = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

        eprintln!(
            "[agent-security] watcher initial file size: {} bytes",
            last_size
        );

        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));

            let size = match fs::metadata(&log_path) {
                Ok(m) => m.len(),
                Err(e) => {
                    // File may not exist yet (agent hasn't started). Keep waiting.
                    eprintln!(
                        "[agent-security] watcher: cannot stat {}: {e}",
                        log_path.display()
                    );
                    0
                }
            };

            if size != last_size {
                eprintln!(
                    "[agent-security] log file changed: {} → {} bytes, emitting agent-events-updated",
                    last_size, size
                );
                last_size = size;
                if let Err(e) = app.emit("agent-events-updated", ()) {
                    eprintln!("[agent-security] watcher: failed to emit event: {e}");
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
            match project_root() {
                Ok(root) => {
                    eprintln!("[agent-security] project root:  {}", root.display());
                }
                Err(e) => {
                    eprintln!("[agent-security] ERROR resolving project root: {e}");
                }
            }

            let log_path = match ensure_runtime_dirs() {
                Ok(p) => {
                    let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    eprintln!(
                        "[agent-security] watching log file: {} ({} bytes)",
                        p.display(),
                        size
                    );
                    p
                }
                Err(e) => {
                    eprintln!("[agent-security] ERROR setting up runtime dirs: {e}");
                    // Fall back to whatever path we can derive, even if the file is missing.
                    log_file_path().unwrap_or_else(|_| PathBuf::from("runtime/logs/agent-events.jsonl"))
                }
            };

            // ── System tray ───────────────────────────────────────────────────
            use tauri::tray::{TrayIconBuilder, TrayIconEvent};

            if let Some(icon) = app.default_window_icon().cloned() {
                let _ = TrayIconBuilder::new()
                    .icon(icon)
                    .tooltip("Agent Security")
                    .on_tray_icon_event(|tray, event| {
                        if matches!(event, TrayIconEvent::Click { .. }) {
                            let app = tray.app_handle();
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    })
                    .build(app.handle());
            }

            start_log_watcher(app.handle().clone(), log_path);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
