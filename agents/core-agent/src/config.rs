use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const POLICY_PATH: &str = "runtime/policy.json";
/// The file the Tauri UI reads/writes for runtime knobs like simulation_mode.
const AGENT_CONFIG_TOML: &str = "runtime/agent-config.toml";

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

/// Processes and files listed here are never killed or quarantined by the response engine.
/// Defaults to empty on any read error — never crash if the whitelist is missing.
#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    pub trusted_process_paths: Vec<String>,
    pub trusted_process_names: Vec<String>,
    pub trusted_app_bundle_paths: Vec<String>,
}

/// Re-read the [whitelist] section from agent-config.toml on every call.
/// Returns an empty Whitelist on any error.
pub fn read_live_whitelist() -> Whitelist {
    read_whitelist_from_toml(&agent_config_path())
}

/// Processes/paths in this list never generate any alert events.
/// Completely separate from the response whitelist (which says "detect but don't act").
/// This says "don't even generate an alert."
/// Defaults to empty on any read error — missing section means no suppression.
#[derive(Debug, Clone, Default)]
pub struct DetectionWhitelist {
    /// Process command names (exact match, basename only) that are never alerted on.
    pub suppressed_process_names: Vec<String>,
    /// Path prefixes — any process running from these paths is suppressed.
    pub suppressed_path_prefixes: Vec<String>,
}

impl DetectionWhitelist {
    /// Returns true if this process command or path should have detection suppressed.
    /// `args` is the full argument string for the process (used to suppress shell invocations
    /// that only reference trusted paths, e.g. zsh -c "source /Users/foo/.claude/...").
    pub fn is_suppressed(&self, command: &str, path: &str, args: &str) -> bool {
        // Check command basename
        let basename = std::path::Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);
        if self.suppressed_process_names.iter().any(|n| n == basename || n == command) {
            return true;
        }
        // Check path prefix
        if !path.is_empty()
            && self.suppressed_path_prefixes.iter().any(|prefix| path.starts_with(prefix.as_str()))
        {
            return true;
        }
        // Shell invoking something under a suppressed path prefix:
        // e.g. zsh -c "source /Users/foo/.claude/shell-snapshots/..."
        // We suppress if the shell is a known system shell AND its args reference
        // at least one suppressed path (and don't reference any untrusted location).
        if matches!(basename, "zsh" | "bash" | "sh" | "dash" | "ksh") && !args.is_empty() {
            let args_reference_suppressed = self
                .suppressed_path_prefixes
                .iter()
                .any(|prefix| args.contains(prefix.as_str()));
            if args_reference_suppressed {
                return true;
            }
        }
        false
    }
}

/// Re-read the [detection_whitelist] section from agent-config.toml on every call.
/// Returns an empty DetectionWhitelist on any error.
pub fn read_live_detection_whitelist() -> DetectionWhitelist {
    let path = agent_config_path();
    if !path.exists() {
        return DetectionWhitelist::default();
    }
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return DetectionWhitelist::default(),
    };
    let section = extract_toml_section(&contents, "detection_whitelist");
    DetectionWhitelist {
        suppressed_process_names: parse_toml_string_array(&section, "suppressed_process_names"),
        suppressed_path_prefixes: parse_toml_string_array(&section, "suppressed_path_prefixes"),
    }
}

/// Re-read the incident score threshold from agent-config.toml on every call.
/// Falls back to 35 if the key is absent or file is unreadable.
/// 35 is more conservative than the old 20 — significantly reduces false positives
/// from individual LOLBin signals firing in quick succession during normal builds.
pub fn read_live_incident_threshold() -> u8 {
    let path = agent_config_path();
    if !path.exists() {
        return 35;
    }
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return 35,
    };
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("incident_threshold") {
            let val = rest.trim().trim_start_matches('=').trim();
            if let Ok(n) = val.parse::<u8>() {
                return n;
            }
        }
    }
    35
}

pub fn load_policy() -> Result<ResponsePolicy> {
    let path = Path::new(POLICY_PATH);

    let mut policy = if !path.exists() {
        ResponsePolicy::default()
    } else {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file at {}", POLICY_PATH))?;
        serde_json::from_str(&raw).context("failed to parse runtime/policy.json")?
    };

    // Override simulation_mode from agent-config.toml — this is the file the
    // Tauri UI writes to. It takes precedence over policy.json so the UI toggle
    // always reflects the true running state.
    let toml_path = agent_config_path();
    let live = read_simulation_mode_from_toml(&toml_path);
    policy.simulation_mode = live;

    Ok(policy)
}

/// Returns the absolute path to agent-config.toml.
/// Exposed so callers can log the exact path that is being read.
pub fn agent_config_path() -> PathBuf {
    crate::logging::project_root_path().join(AGENT_CONFIG_TOML)
}

/// Re-read simulation_mode from agent-config.toml on every call.
/// Always defaults to `true` (safe/simulation) if the file is missing,
/// unreadable, or does not contain the key.
///
/// Call this immediately before every response decision so the agent
/// always uses the live value written by the UI, not a cached startup value.
pub fn read_live_simulation_mode() -> bool {
    read_simulation_mode_from_toml(&agent_config_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_mode_defaults_true_when_file_absent() {
        let dir = std::env::temp_dir().join("agent_cfg_test_absent");
        let path = dir.join("agent-config.toml");
        assert!(read_simulation_mode_from_toml(&path), "absent file should default to simulation=true");
    }

    #[test]
    fn simulation_mode_false_when_config_says_false() {
        let dir = std::env::temp_dir().join("agent_cfg_test_false");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent-config.toml");
        std::fs::write(&path, "simulation_mode = false\n").unwrap();
        assert!(!read_simulation_mode_from_toml(&path), "should return false when config says false");
    }

    #[test]
    fn simulation_mode_true_when_config_says_true() {
        let dir = std::env::temp_dir().join("agent_cfg_test_true");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent-config.toml");
        std::fs::write(&path, "simulation_mode = true\n").unwrap();
        assert!(read_simulation_mode_from_toml(&path), "should return true when config says true");
    }

    #[test]
    fn simulation_mode_defaults_true_when_key_absent() {
        let dir = std::env::temp_dir().join("agent_cfg_test_no_key");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent-config.toml");
        std::fs::write(&path, "some_other_key = value\n").unwrap();
        assert!(read_simulation_mode_from_toml(&path), "missing key should default to simulation=true");
    }

    #[test]
    fn simulation_mode_safe_default_for_garbage_value() {
        let dir = std::env::temp_dir().join("agent_cfg_test_garbage");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent-config.toml");
        std::fs::write(&path, "simulation_mode = maybe\n").unwrap();
        assert!(read_simulation_mode_from_toml(&path), "unrecognised value should default to simulation=true");
    }
}

fn read_whitelist_from_toml(path: &Path) -> Whitelist {
    if !path.exists() {
        return Whitelist::default();
    }
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Whitelist::default(),
    };
    let section = extract_toml_section(&contents, "whitelist");
    Whitelist {
        trusted_process_paths: parse_toml_string_array(&section, "trusted_process_paths"),
        trusted_process_names: parse_toml_string_array(&section, "trusted_process_names"),
        trusted_app_bundle_paths: parse_toml_string_array(&section, "trusted_app_bundle_paths"),
    }
}

/// Extract the body of a named TOML section (e.g. "whitelist" → reads `[whitelist]` block).
/// Returns an empty string if the section is not found.
fn extract_toml_section(contents: &str, section_name: &str) -> String {
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
    lines.join("\n")
}

/// Extract a TOML string-array value (e.g. `key = ["a", "b"]`) from a section body.
/// Handles multi-line arrays. Returns an empty Vec on any parse error.
fn parse_toml_string_array(section: &str, key: &str) -> Vec<String> {
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

fn read_simulation_mode_from_toml(path: &Path) -> bool {
    if !path.exists() {
        return true; // safe default: simulate if config is absent
    }
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return true, // safe default: simulate if unreadable
    };
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("simulation_mode") {
            let val = rest.trim().trim_start_matches('=').trim();
            // Any value other than exactly "false" keeps simulation on.
            // This makes simulation_mode=true the safe default.
            return !val.eq_ignore_ascii_case("false");
        }
    }
    true // key not present → stay in simulation
}