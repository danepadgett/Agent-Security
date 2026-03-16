use std::fs;
use std::path::PathBuf;

#[tauri::command]
fn read_agent_events() -> Result<Vec<String>, String> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // desktop
        .and_then(|p| p.parent()) // apps
        .and_then(|p| p.parent()) // personal-cyber-platform
        .ok_or("failed to resolve project root")?
        .to_path_buf();

    let log_file = project_root
        .join("runtime")
        .join("logs")
        .join("agent-events.jsonl");

    if !log_file.exists() {
        return Ok(vec![]);
    }

    let contents =
        fs::read_to_string(&log_file).map_err(|e| format!("failed to read log file: {e}"))?;

    let lines = contents
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<String>>();

    Ok(lines)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![read_agent_events])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}