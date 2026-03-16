use crate::classify::classify_path;
use crate::config::ResponsePolicy;
use std::path::Path;

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

pub fn should_allow_file_quarantine(path: &str, policy: &ResponsePolicy) -> Result<(), String> {
    if path_kind_is_safe(path, policy) {
        return Err(format!(
            "path kind {} is protected by response guardrails",
            path_kind(path)
        ));
    }

    if extension_is_safe(path, policy) {
        return Err(format!(
            "file extension .{} is safelisted",
            file_extension(path)
        ));
    }

    if !extension_is_quarantine_candidate(path, policy) {
        return Err(format!(
            "file extension .{} is not an approved quarantine candidate",
            file_extension(path)
        ));
    }

    Ok(())
}

pub fn should_allow_process_kill(
    process_kind: Option<&str>,
    path: Option<&str>,
    policy: &ResponsePolicy,
) -> Result<(), String> {
    if process_kind_is_safe(process_kind, policy) {
        return Err(format!(
            "process kind {} is protected by response guardrails",
            process_kind.unwrap_or("unknown")
        ));
    }

    if let Some(path) = path {
        if path_kind_is_safe(path, policy) {
            return Err(format!(
                "associated path kind {} is protected by response guardrails",
                path_kind(path)
            ));
        }
    }

    Ok(())
}