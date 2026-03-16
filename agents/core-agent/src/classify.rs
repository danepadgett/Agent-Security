use std::path::Path;

pub fn classify_process_command(command: &str) -> String {
    let lower = command.to_ascii_lowercase();

    if is_script_interpreter(command) {
        return "interpreter".to_string();
    }

    if is_browser_process(command) {
        return "browser".to_string();
    }

    if lower.starts_with("/system/")
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.starts_with("/library/apple/")
    {
        return "system".to_string();
    }

    if lower.starts_with("/applications/")
        || lower.contains("/applications/")
        || lower.starts_with("/users/")
    {
        return "user_app".to_string();
    }

    "unknown".to_string()
}

pub fn classify_path(path: &str) -> String {
    let lower = path.to_ascii_lowercase();

    if is_persistence_path(path) {
        return "persistence".to_string();
    }

    if lower.contains("/downloads/") {
        return "downloads".to_string();
    }

    if lower.starts_with("/system/")
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.starts_with("/library/")
    {
        return "system_space".to_string();
    }

    if lower.starts_with("/users/") {
        return "user_space".to_string();
    }

    "unknown".to_string()
}

pub fn is_persistence_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();

    lower.contains("/library/launchagents/")
        || lower.contains("/library/launchdaemons/")
        || (lower.ends_with(".plist") && lower.contains("launchagents"))
        || (lower.ends_with(".plist") && lower.contains("launchdaemons"))
}

pub fn is_script_interpreter(command: &str) -> bool {
    let filename = Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();

    matches!(
        filename.as_str(),
        "sh" | "bash" | "zsh" | "python" | "python3" | "osascript"
    )
}

fn is_browser_process(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();

    lower.contains("safari")
        || lower.contains("chrome")
        || lower.contains("firefox")
        || lower.contains("brave")
        || lower.contains("arc")
}