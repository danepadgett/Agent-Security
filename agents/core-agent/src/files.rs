use crate::models::{FileEvent, FileSnapshot, FileSnapshotMap, TelemetryEvent};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::UNIX_EPOCH;
use walkdir::{DirEntry, WalkDir};

// ── Watched directories ────────────────────────────────────────────────────────

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
        // Cloud credential files (T1552.001 — Credentials in Files)
        PathBuf::from(format!("{home}/.azure")),
        PathBuf::from(format!("{home}/.config/gcloud")),
        PathBuf::from(format!("{home}/.kube")),
        PathBuf::from(format!("{home}/.docker")),
        // Login item persistence — BTM database (T1547.001)
        PathBuf::from("/var/db/com.apple.backgroundtaskmanagement"),
    ]
}

// ── FSEvents-based file monitor ────────────────────────────────────────────────

/// Push-based file monitor backed by macOS FSEvents (via the `notify` crate).
///
/// On each main-loop tick, call `drain_events()`.  If no files have changed the
/// call returns in microseconds.  If files have changed, only the changed paths
/// are re-stat'd — no full directory walk.
pub struct FileMonitor {
    /// Known state of every tracked file (updated incrementally).
    snapshot: FileSnapshotMap,
    /// Receives FSEvents notifications from the background watcher thread.
    rx: mpsc::Receiver<notify::Result<notify::Event>>,
    /// Held to keep the FSEvents subscription alive.  Dropping this stops watching.
    _watcher: RecommendedWatcher,
    /// Canonical set of watched root directories (used for path filtering).
    watch_dirs: Vec<PathBuf>,
}

impl FileMonitor {
    /// Initialise the monitor:
    ///   1. Take one full snapshot of all watched directories (baseline).
    ///   2. Register FSEvents watches so future changes arrive via `drain_events`.
    pub fn new(directories: &[PathBuf]) -> Result<Self> {
        // Baseline snapshot — one-time walk, same logic as before.
        let snapshot = scan_directories(directories)?;
        eprintln!(
            "[file_monitor] baseline snapshot: {} files across {} directories",
            snapshot.len(),
            directories.len()
        );

        // Channel connecting the watcher callback to the main loop.
        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();

        // Use a 250ms FSEvents coalescing latency so events arrive within one
        // main-loop tick rather than the 2s default.  On macOS this maps directly
        // to the kFSEventStream latency parameter.
        let config = Config::default()
            .with_poll_interval(std::time::Duration::from_millis(250));

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                // Silently drop if the receiver has gone away (e.g. during shutdown).
                let _ = tx.send(res);
            },
            config,
        )
        .context("failed to create FSEvents watcher")?;

        // Register each existing directory.  Non-existent paths (e.g. ~/.aws on a
        // machine that has never run the AWS CLI) are silently skipped.
        let mut registered = 0usize;
        for dir in directories {
            if !dir.exists() {
                continue;
            }
            match watcher.watch(dir, RecursiveMode::Recursive) {
                Ok(()) => {
                    registered += 1;
                    eprintln!("[file_monitor] watching: {}", dir.display());
                }
                Err(e) => {
                    eprintln!(
                        "[file_monitor] WARNING: could not watch {}: {e}",
                        dir.display()
                    );
                }
            }
        }
        eprintln!("[file_monitor] FSEvents registered on {registered} paths");

        Ok(Self {
            snapshot,
            rx,
            _watcher: watcher,
            watch_dirs: directories.to_vec(),
        })
    }

    /// Drain all pending FSEvents notifications and return file events.
    ///
    /// - If nothing has changed: returns empty Vec in a few microseconds.
    /// - If files changed: re-stats only the changed paths, diffs against the
    ///   snapshot, generates events, and updates the snapshot.
    pub fn drain_events(&mut self, now: DateTime<Utc>) -> Vec<FileEvent> {
        // Collect every changed path from the channel, deduplicated.
        let mut changed_paths: HashSet<PathBuf> = HashSet::new();
        loop {
            match self.rx.try_recv() {
                Ok(Ok(event)) => {
                    for path in event.paths {
                        changed_paths.insert(path);
                    }
                }
                Ok(Err(e)) => eprintln!("[file_monitor] watcher error: {e}"),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    eprintln!("[file_monitor] watcher channel disconnected");
                    break;
                }
            }
        }

        if changed_paths.is_empty() {
            return Vec::new();
        }

        let mut events = Vec::new();

        for path in changed_paths {
            // Skip paths that aren't under a watched root (e.g. temp-file renames
            // from outside our tree that FSEvents delivers as a side-effect).
            if !self.is_watched_path(&path) {
                continue;
            }

            match fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => {
                    let current = Self::snapshot_from_metadata(&path, &metadata);

                    match self.snapshot.get(&path) {
                        None => {
                            // New file observed for the first time.
                            events.push(build_file_event("file_created", path.clone(), &current, now));
                            self.snapshot.insert(path, current);
                        }
                        Some(old) => {
                            if old.modified_unix_seconds != current.modified_unix_seconds
                                || old.size_bytes != current.size_bytes
                            {
                                events.push(build_file_event("file_modified", path.clone(), &current, now));
                            }
                            if !old.is_executable && current.is_executable {
                                events.push(build_file_event(
                                    "file_became_executable",
                                    path.clone(),
                                    &current,
                                    now,
                                ));
                            }
                            if !old.has_quarantine && current.has_quarantine {
                                events.push(build_file_event(
                                    "file_gained_quarantine",
                                    path.clone(),
                                    &current,
                                    now,
                                ));
                            }
                            self.snapshot.insert(path, current);
                        }
                    }
                }
                Ok(_) => {
                    // A directory or symlink — nothing to do.
                }
                Err(_) => {
                    // File deleted or inaccessible — remove from snapshot so a
                    // future re-creation shows up as file_created again.
                    self.snapshot.remove(&path);
                }
            }
        }

        events
    }

    fn is_watched_path(&self, path: &Path) -> bool {
        self.watch_dirs.iter().any(|dir| path.starts_with(dir))
    }

    fn snapshot_from_metadata(path: &Path, metadata: &fs::Metadata) -> FileSnapshot {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mode = metadata.permissions().mode();
        let is_executable = mode & 0o111 != 0;
        let quarantine_value = get_quarantine_xattr(path);
        let has_quarantine = quarantine_value.is_some();

        FileSnapshot {
            modified_unix_seconds: modified,
            size_bytes: metadata.len(),
            is_executable,
            has_quarantine,
            quarantine_value,
        }
    }
}

// ── Internal scan helpers (used for the initial baseline snapshot) ─────────────

fn scan_directories(directories: &[PathBuf]) -> Result<FileSnapshotMap> {
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
            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue, // Race: file disappeared between walk and stat
            };

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

// ── Event builder ──────────────────────────────────────────────────────────────

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

// ── Magic bytes detection ──────────────────────────────────────────────────────

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

// ── Walk helpers (used by the initial scan only) ───────────────────────────────

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

// ── xattr helpers ──────────────────────────────────────────────────────────────

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
