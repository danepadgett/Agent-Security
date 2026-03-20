use std::path::Path;

pub fn classify_path(path: &str) -> String {
    let normalized = normalize_token(path);
    let lower = normalized.to_ascii_lowercase();

    if is_persistence_path(&lower) {
        return "persistence".to_string();
    }

    if lower.contains("/downloads/") {
        return "downloads".to_string();
    }

    if lower.contains("/desktop/") {
        return "desktop".to_string();
    }

    if lower.contains("/documents/") {
        return "documents".to_string();
    }

    if lower.starts_with("/system/")
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.starts_with("/private/var/db/")
        || lower.starts_with("/library/apple/")
    {
        return "system".to_string();
    }

    if lower.contains("/applications/") || lower.ends_with(".app") || lower.contains(".app/") {
        return "user_app".to_string();
    }

    "unknown".to_string()
}

pub fn classify_process_command(command: &str) -> String {
    let normalized = normalize_token(command);
    let lower = normalized.to_ascii_lowercase();
    let base = basename(&normalized);

    if is_browser_command(&normalized) {
        return "browser".to_string();
    }

    if is_script_interpreter(&normalized)
        || is_network_tool(&normalized)
        || is_persistence_tool_command(&normalized)
    {
        return "interpreter".to_string();
    }

    if lower.starts_with("/system/")
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
    {
        return "system".to_string();
    }

    if lower.contains("/applications/") || base.ends_with(".app") {
        return "user_app".to_string();
    }

    "unknown".to_string()
}

pub fn is_script_interpreter(command: &str) -> bool {
    matches!(
        basename(&normalize_token(command)).as_str(),
        "bash"
            | "sh"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "python"
            | "python3"
            | "osascript"
            | "perl"
            | "ruby"
            | "node"
    )
}

pub fn is_network_tool(command: &str) -> bool {
    matches!(basename(&normalize_token(command)).as_str(), "curl" | "wget")
}

pub fn is_persistence_tool_command(command: &str) -> bool {
    matches!(
        basename(&normalize_token(command)).as_str(),
        "launchctl" | "crontab" | "osascript" | "defaults"
    )
}

pub fn is_persistence_path(path: &str) -> bool {
    let lower = normalize_token(path).to_ascii_lowercase();

    lower.contains("/library/launchagents/")
        || lower.contains("/library/launchdaemons/")
        || lower == "/etc/crontab"
        || lower == "/private/etc/crontab"
        || lower.starts_with("/usr/lib/cron/tabs/")
        || lower.starts_with("/private/var/at/tabs/")
        || lower.contains("/library/preferences/com.apple.loginwindow.plist")
        || (lower.ends_with(".plist")
            && (lower.contains("/launchagents/")
                || lower.contains("/launchdaemons/")
                || lower.contains("loginwindow")))
}

pub fn is_browser_command(command: &str) -> bool {
    matches!(
        basename(&normalize_token(command)).as_str(),
        "safari"
            | "google chrome"
            | "chrome"
            | "firefox"
            | "arc"
            | "brave browser"
            | "brave"
            | "microsoft edge"
            | "edge"
    )
}

pub fn is_benign_developer_tool_command(command: &str, args: &str) -> bool {
    let name = basename(&normalize_token(command));
    let args_lower = args.to_ascii_lowercase();

    match name.as_str() {
        "cargo" | "rustc" | "rust-analyzer" | "sccache" | "brew" | "git" | "make" | "cmake"
        | "xcodebuild" | "swift" | "swiftc" | "pod" | "gem" | "bundle" | "poetry" | "uv"
        | "bun" | "npm" | "npx" | "yarn" => true,
        "python" | "python3" => {
            args_lower.starts_with("-m pip")
                || args_lower.starts_with("-m venv")
                || args_lower.contains("site-packages")
        }
        "pip" | "pip3" => true,
        "node" => {
            args_lower.contains("node_modules")
                || args_lower.contains("npm")
                || args_lower.contains("vite")
                || args_lower.contains("next")
        }
        _ => false,
    }
}

pub fn is_benign_admin_tool_command(command: &str, args: &str) -> bool {
    let name = basename(&normalize_token(command));
    let args_lower = args.to_ascii_lowercase();

    match name.as_str() {
        "softwareupdate" | "installer" => true,
        "defaults" => {
            args_lower.contains("com.apple")
                && !args_lower.contains("loginwindow")
                && !args_lower.contains("login item")
        }
        _ => false,
    }
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_ascii_lowercase()
}

fn normalize_token(value: &str) -> String {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return String::new();
    }

    let without_parens = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed)
        .trim();

    without_parens.to_string()
}