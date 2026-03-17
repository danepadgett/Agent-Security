use crate::classify::classify_path;
use crate::config::ResponsePolicy;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ProcessKillRequest<'a> {
    pub pid: i32,
    pub process_kind: Option<&'a str>,
    pub associated_path: Option<&'a str>,
    pub score: u8,
    pub original_event_type: &'a str,
    pub chain_root_pid: Option<i32>,
    pub is_root_process: bool,
    pub attack_chain_length: usize,
    pub confidence: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct FileQuarantineRequest<'a> {
    pub path: &'a str,
    pub score: u8,
    pub original_event_type: &'a str,
    pub path_kind: &'a str,
    pub confidence: Option<&'a str>,
    pub attack_chain_length: usize,
}

pub fn file_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

pub fn path_kind(path: &str) -> String {
    classify_path(path)
}

pub fn process_kind_is_safe(process_kind: Option<&str>, policy: &ResponsePolicy) -> bool {
    let Some(kind) = process_kind else {
        return false;
    };

    policy
        .safe_process_kinds
        .iter()
        .any(|safe| safe.eq_ignore_ascii_case(kind))
}

pub fn path_kind_is_safe(path: &str, policy: &ResponsePolicy) -> bool {
    let kind = path_kind(path);
    policy
        .safe_path_kinds
        .iter()
        .any(|safe| safe.eq_ignore_ascii_case(&kind))
}

pub fn extension_is_safe(path: &str, policy: &ResponsePolicy) -> bool {
    let ext = file_extension(path);
    if ext.is_empty() {
        return false;
    }

    policy
        .safe_file_extensions
        .iter()
        .any(|safe| safe.eq_ignore_ascii_case(&ext))
}

pub fn extension_is_quarantine_candidate(path: &str, policy: &ResponsePolicy) -> bool {
    let ext = file_extension(path);
    if ext.is_empty() {
        return false;
    }

    policy
        .quarantine_candidate_extensions
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&ext))
}

pub fn should_allow_file_quarantine(
    request: &FileQuarantineRequest,
    policy: &ResponsePolicy,
) -> Result<(), String> {
    if path_kind_is_safe(request.path, policy) {
        return Err(format!(
            "path kind {} is protected by response guardrails",
            path_kind(request.path)
        ));
    }

    if extension_is_safe(request.path, policy) {
        return Err(format!(
            "file extension .{} is safelisted",
            file_extension(request.path)
        ));
    }

    if !extension_is_quarantine_candidate(request.path, policy) {
        return Err(format!(
            "file extension .{} is not an approved quarantine candidate",
            file_extension(request.path)
        ));
    }

    let ext = file_extension(request.path);
    let high_risk_ext = matches!(
        ext.as_str(),
        "app" | "pkg" | "dmg" | "xip" | "zip" | "sh" | "command" | "py" | "js" | "scpt" | "jar" | "bin"
    );

    let high_confidence = matches!(request.confidence, Some("high"));

    if request.original_event_type != "alert_behavioral_incident" && request.score < 85 {
        return Err(format!(
            "file quarantine for non-incident alerts requires score >= 85 (got score {})",
            request.score
        ));
    }

    if request.path_kind != "downloads"
        && !high_risk_ext
        && !(high_confidence && request.attack_chain_length >= 2)
        && request.score < 92
    {
        return Err(format!(
            "quarantine outside Downloads requires a high-risk extension, or high-confidence chain context, or score >= 92 (got score {})",
            request.score
        ));
    }

    Ok(())
}

pub fn should_allow_process_kill(
    request: &ProcessKillRequest,
    policy: &ResponsePolicy,
) -> Result<(), String> {
    if process_kind_is_safe(request.process_kind, policy) {
        return Err(format!(
            "process kind {} is protected by response guardrails",
            request.process_kind.unwrap_or("unknown")
        ));
    }

    if let Some(path) = request.associated_path {
        if path_kind_is_safe(path, policy) {
            return Err(format!(
                "associated path kind {} is protected by response guardrails",
                path_kind(path)
            ));
        }
    }

    if request.original_event_type != "alert_behavioral_incident" && request.score < 90 {
        return Err(format!(
            "process kill for non-incident alerts requires score >= 90 (got score {})",
            request.score
        ));
    }

    if request.is_root_process {
        let high_confidence = matches!(request.confidence, Some("high"));
        if request.score < 95 && !(high_confidence && request.attack_chain_length >= 3) {
            return Err(format!(
                "root-process kill requires score >= 95 or high-confidence deep-chain context (got score {})",
                request.score
            ));
        }
    }

    if request.process_kind.is_none() && request.associated_path.is_none() && request.score < 92 {
        return Err(format!(
            "unclassified process kill requires score >= 92 when no path context exists (got score {})",
            request.score
        ));
    }

    let _ = request.pid;
    let _ = request.chain_root_pid;

    Ok(())
}