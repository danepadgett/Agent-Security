use crate::models::{FileEvent, FileSnapshot, FileSnapshotMap, TelemetryEvent};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use walkdir::{DirEntry, WalkDir};

pub fn tracked_directories() -> Vec<PathBuf> {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());

    vec![
        PathBuf::from(format!("{home}/Downloads")),
        PathBuf::from(format!("{home}/Desktop")),
        PathBuf::from(format!("{home}/Documents")),
        PathBuf::from(format!("{home}/Library/LaunchAgents")),
        PathBuf::from(format!("{home}/Library/LaunchDaemons")),
        PathBuf::from("/etc/periodic/daily"),
        PathBuf::from("/etc/periodic/weekly"),
        PathBuf::from("/etc/periodic/monthly"),
        // Credential access monitoring (T1552.004, T1552.001)
        PathBuf::from(format!("{home}/.ssh")),
        PathBuf::from(format!("{home}/.aws")),
        // Login item persistence — BTM database (T1547.001)
        PathBuf::from("/var/db/com.apple.backgroundtaskmanagement"),
    ]
}

pub fn scan_directories(directories: &[PathBuf]) -> Result<FileSnapshotMap> {
    let mut snapshot: FileSnapshotMap = HashMap::new();

    for dir in directories {
        if !dir.exists() {
            continue;
        }

        let walker = WalkDir::new(dir)
            .into_iter()
            .filter_entry(|entry| should_descend(entry, dir));

        for entry in walker.filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
            let path = entry.path().to_path_buf();
            let metadata = fs::metadata(&path)
                .with_context(|| format!("failed to read metadata for {}", path.display()))?;

            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let mode = metadata.permissions().mode();
            let is_executable = mode & 0o111 != 0;

            let quarantine_value = get_quarantine_xattr(&path);
            let has_quarantine = quarantine_value.is_some();

            snapshot.insert(
                path,
                FileSnapshot {
                    modified_unix_seconds: modified,
                    size_bytes: metadata.len(),
                    is_executable,
                    has_quarantine,
                    quarantine_value,
                },
            );
        }
    }

    Ok(snapshot)
}

pub fn collect_file_events(
    directories: &[PathBuf],
    previous: &FileSnapshotMap,
    now: DateTime<Utc>,
) -> Result<(FileSnapshotMap, Vec<FileEvent>)> {
    let current = scan_directories(directories)?;
    let mut events = Vec::new();

    for (path, current_meta) in &current {
        match previous.get(path) {
            None => {
                events.push(build_file_event("file_created", path.clone(), current_meta, now));
            }
            Some(old_meta) => {
                if old_meta.modified_unix_seconds != current_meta.modified_unix_seconds
                    || old_meta.size_bytes != current_meta.size_bytes
                {
                    events.push(build_file_event("file_modified", path.clone(), current_meta, now));
                }

                if !old_meta.is_executable && current_meta.is_executable {
                    events.push(build_file_event(
                        "file_became_executable",
                        path.clone(),
                        current_meta,
                        now,
                    ));
                }

                if !old_meta.has_quarantine && current_meta.has_quarantine {
                    events.push(build_file_event(
                        "file_gained_quarantine",
                        path.clone(),
                        current_meta,
                        now,
                    ));
                }
            }
        }
    }

    Ok((current, events))
}

fn build_file_event(
    kind: &str,
    path: PathBuf,
    snapshot: &FileSnapshot,
    now: DateTime<Utc>,
) -> FileEvent {
    // Only read magic bytes for new or modified files — not for permission/quarantine changes.
    let magic_hint = if matches!(kind, "file_created" | "file_modified") {
        read_magic_bytes_hint(&path)
    } else {
        None
    };

    let telemetry_event = TelemetryEvent::new(
        now,
        kind,
        "core-agent/files",
        json!({
            "path": path.to_string_lossy(),
            "size_bytes": snapshot.size_bytes,
            "is_executable": snapshot.is_executable,
            "has_quarantine": snapshot.has_quarantine,
            "quarantine_value": snapshot.quarantine_value,
            "magic_bytes_hint": magic_hint,
        }),
    );

    FileEvent {
        kind: kind.to_string(),
        path,
        timestamp: now,
        telemetry_event,
    }
}

/// Read the first 8 bytes of `path` and return a short tag for the file type.
///
/// Recognized signatures:
///   `\x7fELF`              → "elf"        (Linux/ELF — suspicious on macOS)
///   `\xcf\xfa\xed\xfe`     → "macho64"    (Mach-O 64-bit little-endian)
///   `\xce\xfa\xed\xfe`     → "macho32"    (Mach-O 32-bit little-endian)
///   `\xca\xfe\xba\xbe`     → "macho_fat"  (Mach-O universal / fat binary)
///   `PK\x03\x04`           → "zip"
///   `%PDF`                 → "pdf"
///   `\xff\xd8\xff`         → "jpeg"
///   `\x89PNG`              → "png"
///
/// Returns None when the file cannot be read or bytes match no known signature.
pub fn read_magic_bytes_hint(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut buf = [0u8; 8];
    let mut f = fs::File::open(path).ok()?;
    let n = f.read(&mut buf).ok()?;
    if n < 4 {
        return None;
    }

    let tag = match &buf[..4] {
        [0x7f, b'E', b'L', b'F'] => "elf",
        [0xcf, 0xfa, 0xed, 0xfe] => "macho64",
        [0xce, 0xfa, 0xed, 0xfe] => "macho32",
        [0xca, 0xfe, 0xba, 0xbe] => "macho_fat",
        [b'P', b'K', 0x03, 0x04] => "zip",
        [b'%', b'P', b'D', b'F'] => "pdf",
        [0xff, 0xd8, 0xff, _] => "jpeg",
        [0x89, b'P', b'N', b'G'] => "png",
        _ => return None,
    };

    Some(tag.to_string())
}

fn should_descend(entry: &DirEntry, root: &Path) -> bool {
    if entry.depth() == 0 {
        return true;
    }

    let path = entry.path();

    if entry.file_type().is_dir() {
        if is_bundle_like_dir(path) && !is_top_level_child(path, root) {
            return false;
        }

        if is_bundle_like_dir(path) && is_top_level_child(path, root) {
            return false;
        }
    }

    true
}

fn is_top_level_child(path: &Path, root: &Path) -> bool {
    match path.parent() {
        Some(parent) => parent == root,
        None => false,
    }
}

fn is_bundle_like_dir(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.ends_with(".app")
        || lower.ends_with(".pkg")
        || lower.ends_with(".dmg")
        || lower.ends_with(".zip")
        || lower.ends_with(".xip")
}

fn get_quarantine_xattr(path: &Path) -> Option<String> {
    let path_str = path.to_str()?;
    let c_path = CString::new(path_str).ok()?;
    let c_name = CString::new("com.apple.quarantine").ok()?;

    unsafe {
        let size = libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            0,
        );

        if size <= 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let result = libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0,
            0,
        );

        if result <= 0 {
            return None;
        }

        buffer.truncate(result as usize);

        while matches!(buffer.last(), Some(0)) {
            buffer.pop();
        }

        String::from_utf8(buffer).ok()
    }
}