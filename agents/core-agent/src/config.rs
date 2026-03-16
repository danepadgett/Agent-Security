use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const POLICY_PATH: &str = "runtime/policy.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub simulation_mode: bool,
    pub enable_process_kill: bool,
    pub enable_file_quarantine: bool,
    pub kill_threshold: u8,
    pub quarantine_threshold: u8,
    pub safe_process_kinds: Vec<String>,
    pub safe_path_kinds: Vec<String>,
    pub safe_file_extensions: Vec<String>,
    pub quarantine_candidate_extensions: Vec<String>,
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
            simulation_mode: true,
            enable_process_kill: true,
            enable_file_quarantine: true,
            kill_threshold: 85,
            quarantine_threshold: 75,
            safe_process_kinds: vec!["system".to_string(), "browser".to_string()],
            safe_path_kinds: vec!["system_space".to_string(), "persistence".to_string()],
            safe_file_extensions: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "gif".to_string(),
                "pdf".to_string(),
                "ppt".to_string(),
                "pptx".to_string(),
                "doc".to_string(),
                "docx".to_string(),
                "txt".to_string(),
                "md".to_string(),
                "mp3".to_string(),
                "mp4".to_string(),
            ],
            quarantine_candidate_extensions: vec![
                "app".to_string(),
                "pkg".to_string(),
                "dmg".to_string(),
                "zip".to_string(),
                "xip".to_string(),
                "sh".to_string(),
                "command".to_string(),
                "py".to_string(),
                "js".to_string(),
                "scpt".to_string(),
                "jar".to_string(),
                "bin".to_string(),
            ],
        }
    }
}

pub fn load_policy() -> Result<ResponsePolicy> {
    let path = Path::new(POLICY_PATH);

    if !path.exists() {
        return Ok(ResponsePolicy::default());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file at {}", POLICY_PATH))?;

    let policy: ResponsePolicy =
        serde_json::from_str(&raw).context("failed to parse runtime/policy.json")?;

    Ok(policy)
}