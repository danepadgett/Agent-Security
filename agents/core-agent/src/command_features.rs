use crate::classify::is_persistence_path;
use crate::models::ProcessBehaviorFeatures;
use std::collections::BTreeSet;
use std::path::Path;

pub fn extract_features(command: &str, args: &str) -> ProcessBehaviorFeatures {
    let full = if args.trim().is_empty() {
        command.to_string()
    } else {
        format!("{command} {args}")
    };

    let command_name = basename(command);
    let full_lower = full.to_ascii_lowercase();

    let has_pipe = full.contains('|');
    let has_shell_control_operator = ["&&", "||", ";"]
        .iter()
        .any(|operator| full.contains(operator));

    let has_inline_code_execution = has_inline_execution_flag(&command_name, args);
    let uses_network_download_tool = matches!(command_name.as_str(), "curl" | "wget");

    let mut referenced_paths = collect_referenced_paths(command, args);
    if token_looks_like_path(command) {
        referenced_paths.insert(normalize_path_token(command));
    }

    let referenced_urls = collect_referenced_urls(command, args);
    let references_url = !referenced_urls.is_empty();

    let references_downloads_path = referenced_paths.iter().any(|path| path.contains("/Downloads/"));
    let references_persistence_path = referenced_paths
        .iter()
        .any(|path| is_persistence_path(path));

    let references_script_file = referenced_paths.iter().any(|path| is_script_path(path));
    let references_executable_candidate = referenced_paths
        .iter()
        .any(|path| is_executable_candidate_path(path));

    let downloader_family = downloader_family(&command_name, &full_lower);

    let mut suspicious_command_patterns = Vec::new();

    if uses_network_download_tool
        && has_pipe
        && ["bash", "sh", "zsh"]
            .iter()
            .any(|shell| full_lower.contains(shell))
    {
        suspicious_command_patterns.push("network_tool_piped_to_shell".to_string());
    }

    if matches!(command_name.as_str(), "bash" | "sh" | "zsh") && has_inline_code_execution {
        suspicious_command_patterns.push("shell_inline_execution".to_string());
    }

    if matches!(command_name.as_str(), "python" | "python3") && has_inline_code_execution {
        suspicious_command_patterns.push("python_inline_execution".to_string());
    }

    if command_name == "osascript" && args.contains("-e") {
        suspicious_command_patterns.push("osascript_inline_execution".to_string());
    }

    if command_name == "launchctl"
        && ["load", "bootstrap", "enable", "kickstart", "bootout"]
            .iter()
            .any(|token| full_lower.contains(token))
    {
        suspicious_command_patterns.push("launchctl_persistence_operation".to_string());
    }

    if command_name == "crontab" {
        suspicious_command_patterns.push("crontab_persistence_operation".to_string());
    }

    if command_name == "open" && references_executable_candidate {
        suspicious_command_patterns.push("open_executable_candidate".to_string());
    }

    if command_name == "installer" && full_lower.contains(".pkg") {
        suspicious_command_patterns.push("installer_pkg_execution".to_string());
    }

    if full_lower.contains("chmod") && full_lower.contains("+x") {
        suspicious_command_patterns.push("chmod_plus_x".to_string());
    }

    if full.contains("./") {
        suspicious_command_patterns.push("dot_slash_execution".to_string());
    }

    if references_downloads_path && references_script_file {
        suspicious_command_patterns.push("downloads_script_execution".to_string());
    }

    if references_downloads_path && references_executable_candidate {
        suspicious_command_patterns.push("downloads_executable_reference".to_string());
    }

    if references_persistence_path {
        suspicious_command_patterns.push("persistence_path_reference".to_string());
    }

    if references_url && uses_network_download_tool {
        suspicious_command_patterns.push("network_download_with_url".to_string());
    }

    if references_url && references_executable_candidate {
        suspicious_command_patterns.push("url_referenced_with_executable_candidate".to_string());
    }

    suspicious_command_patterns.sort();
    suspicious_command_patterns.dedup();

    let network_indicator_count = usize::from(references_url)
        + usize::from(uses_network_download_tool)
        + referenced_urls.len();

    ProcessBehaviorFeatures {
        has_pipe,
        has_shell_control_operator,
        has_inline_code_execution,
        uses_network_download_tool,
        references_downloads_path,
        references_persistence_path,
        references_script_file,
        references_executable_candidate,
        references_url,
        downloader_family,
        suspicious_command_patterns,
        referenced_paths: referenced_paths.into_iter().collect(),
        referenced_urls,
        token_count: tokenize(&full).len(),
        network_indicator_count,
    }
}

fn has_inline_execution_flag(command_name: &str, args: &str) -> bool {
    let tokens = tokenize(args);

    match command_name {
        "bash" | "sh" | "zsh" => tokens.iter().any(|token| token == "-c"),
        "python" | "python3" => tokens.iter().any(|token| token == "-c"),
        "osascript" => tokens.iter().any(|token| token == "-e"),
        _ => false,
    }
}

fn collect_referenced_paths(command: &str, args: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();

    for token in tokenize(command).into_iter().chain(tokenize(args)) {
        if token_looks_like_path(&token) {
            paths.insert(normalize_path_token(&token));
        }
    }

    paths
}

fn collect_referenced_urls(command: &str, args: &str) -> Vec<String> {
    let mut urls = BTreeSet::new();

    for token in tokenize(command).into_iter().chain(tokenize(args)) {
        let normalized = token
            .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ',' || c == ';')
            .to_string();

        if looks_like_url(&normalized) {
            urls.insert(normalized);
        }
    }

    urls.into_iter().collect()
}

fn looks_like_url(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
}

fn downloader_family(command_name: &str, full_lower: &str) -> Option<String> {
    if matches!(command_name, "curl" | "wget") {
        Some(command_name.to_string())
    } else if command_name == "python" || command_name == "python3" {
        if full_lower.contains("urllib") || full_lower.contains("requests") {
            Some("python_network".to_string())
        } else {
            None
        }
    } else if command_name == "osascript" && full_lower.contains("http") {
        Some("osascript_network".to_string())
    } else {
        None
    }
}

fn tokenize(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .map(|token| token.trim_matches(|c| c == '"' || c == '\'' || c == '`'))
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

fn token_looks_like_path(token: &str) -> bool {
    token.starts_with('/')
        || token.starts_with("./")
        || token.starts_with("../")
        || token.contains("/Downloads/")
        || token.contains("/Desktop/")
        || token.contains("/Documents/")
        || token.contains("/Library/LaunchAgents/")
        || token.contains("/Library/LaunchDaemons/")
        || token.contains("/private/etc/")
        || token.contains("/usr/lib/cron/tabs/")
        || token.contains(".app")
        || token.contains(".pkg")
        || token.contains(".dmg")
        || token.contains(".sh")
        || token.contains(".command")
        || token.contains(".py")
        || token.contains(".js")
        || token.contains(".scpt")
        || token.ends_with(".plist")
}

fn normalize_path_token(token: &str) -> String {
    token
        .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ',' || c == ';')
        .to_string()
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_ascii_lowercase()
}

fn is_script_path(path: &str) -> bool {
    matches!(
        extension(path).as_str(),
        "sh" | "command" | "py" | "js" | "scpt" | "zsh" | "bash"
    )
}

fn is_executable_candidate_path(path: &str) -> bool {
    matches!(
        extension(path).as_str(),
        "app" | "pkg" | "dmg" | "xip" | "zip" | "jar" | "bin"
    )
}

fn extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}