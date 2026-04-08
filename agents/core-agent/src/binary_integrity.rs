/// Binary integrity monitoring for trusted system binaries.
///
/// Records the SHA256 hash of security-sensitive binaries at first run, persists
/// the baseline to `runtime/binary-baseline.json`, and detects when any monitored
/// binary is replaced with a different hash — a key indicator of supply chain
/// compromise (T1195.002).
///
/// Integration:
///   1. Call `load_or_create_baseline()` once at agent startup.
///   2. When a file event arrives for a monitored binary path, call `check_path()`.
///   3. On first execution of a process from a monitored path, call `check_path()`.
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;

pub struct IntegrityViolation {
    pub path: String,
    pub known_hash: String,
    pub current_hash: String,
}

pub struct BinaryIntegrityMonitor {
    /// Maps canonical binary path → known-good SHA256 hex string.
    known_hashes: HashMap<String, String>,
    /// Ordered list of binary paths to monitor.
    monitored_paths: Vec<String>,
}

/// The set of binaries we monitor for replacement.
/// Focused on binaries that are (a) commonly abused and (b) trusted by default.
const MONITORED_BINARIES: &[&str] = &[
    // Package managers
    "/usr/local/bin/brew",
    "/opt/homebrew/bin/brew",
    "/usr/local/bin/npm",
    "/usr/local/bin/node",
    "/opt/homebrew/bin/node",
    // Build/version control
    "/usr/bin/make",
    "/usr/bin/git",
    "/usr/local/bin/git",
    "/opt/homebrew/bin/git",
    // Network tools — highest value supply chain targets
    "/usr/bin/curl",
    "/usr/bin/ssh",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    // Privilege escalation
    "/usr/bin/sudo",
    // Script execution
    "/usr/bin/osascript",
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/usr/bin/python3",
    "/usr/local/bin/python3",
    "/opt/homebrew/bin/python3",
    // Security tools
    "/usr/bin/codesign",
    "/usr/bin/security",
];

impl BinaryIntegrityMonitor {
    pub fn new() -> Self {
        Self {
            known_hashes: HashMap::new(),
            monitored_paths: MONITORED_BINARIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// Load the persisted hash baseline or create a new one by hashing all monitored binaries.
    /// Call this once at agent startup.
    pub fn load_or_create_baseline(&mut self) {
        let baseline_path = crate::logging::project_root_path()
            .join("runtime")
            .join("binary-baseline.json");

        // Attempt to load an existing baseline
        if baseline_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&baseline_path) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&content) {
                    self.known_hashes = map;
                    // Hash any new binaries added since the baseline was created
                    self.extend_baseline_and_save();
                    eprintln!(
                        "[binary_integrity] loaded baseline: {} binaries",
                        self.known_hashes.len()
                    );
                    return;
                }
            }
        }

        // No existing baseline — create one from scratch
        self.record_baseline();
        eprintln!(
            "[binary_integrity] created new baseline: {} binaries hashed",
            self.known_hashes.len()
        );
    }

    fn record_baseline(&mut self) {
        let paths = self.monitored_paths.clone();
        for path in &paths {
            if let Some(hash) = sha256_file(path) {
                self.known_hashes.insert(path.clone(), hash);
            }
        }
        self.save_baseline();
    }

    fn extend_baseline_and_save(&mut self) {
        let paths = self.monitored_paths.clone();
        let mut added = false;
        for path in &paths {
            if !self.known_hashes.contains_key(path.as_str()) {
                if let Some(hash) = sha256_file(path) {
                    self.known_hashes.insert(path.clone(), hash);
                    added = true;
                }
            }
        }
        if added {
            self.save_baseline();
        }
    }

    fn save_baseline(&self) {
        let baseline_path = crate::logging::project_root_path()
            .join("runtime")
            .join("binary-baseline.json");
        if let Ok(json) = serde_json::to_string_pretty(&self.known_hashes) {
            if let Err(e) = std::fs::write(&baseline_path, json) {
                eprintln!("[binary_integrity] failed to save baseline: {e}");
            }
        }
    }

    /// Check whether `path` is a monitored binary.
    pub fn is_monitored(&self, path: &str) -> bool {
        self.monitored_paths.iter().any(|p| p == path)
    }

    /// Check the current hash of `path` against the baseline.
    /// Returns `Some(violation)` if the binary has been replaced, `None` otherwise.
    /// Returns `None` if `path` is not in the baseline (not a monitored binary).
    pub fn check_path(&self, path: &str) -> Option<IntegrityViolation> {
        let known_hash = self.known_hashes.get(path)?;
        let current_hash = sha256_file(path)?;
        if &current_hash != known_hash {
            Some(IntegrityViolation {
                path: path.to_string(),
                known_hash: known_hash.clone(),
                current_hash,
            })
        } else {
            None
        }
    }

    pub fn monitored_paths(&self) -> &[String] {
        &self.monitored_paths
    }
}

/// Compute SHA256 of a file, reading in 64 KB chunks.
/// Returns None if the file cannot be read (missing, permission denied, etc.).
pub fn sha256_file(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_file_returns_none_for_missing_path() {
        assert!(sha256_file("/nonexistent/path/binary").is_none());
    }

    #[test]
    fn sha256_file_returns_some_for_existing_binary() {
        // /bin/sh should exist on every macOS system
        let result = sha256_file("/bin/sh");
        assert!(result.is_some(), "/bin/sh should be hashable");
        let hash = result.unwrap();
        assert_eq!(hash.len(), 64, "SHA256 hex should be 64 chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn is_monitored_returns_true_for_known_binary() {
        let monitor = BinaryIntegrityMonitor::new();
        assert!(monitor.is_monitored("/bin/sh"));
        assert!(monitor.is_monitored("/usr/bin/curl"));
        assert!(monitor.is_monitored("/usr/bin/sudo"));
    }

    #[test]
    fn is_monitored_returns_false_for_unknown_path() {
        let monitor = BinaryIntegrityMonitor::new();
        assert!(!monitor.is_monitored("/usr/bin/caffeinate"));
        assert!(!monitor.is_monitored("/Applications/Safari.app/Contents/MacOS/Safari"));
    }

    #[test]
    fn check_path_returns_none_when_path_not_in_baseline() {
        let monitor = BinaryIntegrityMonitor::new();
        // No baseline loaded — known_hashes is empty — check_path returns None
        assert!(monitor.check_path("/bin/sh").is_none());
    }
}
