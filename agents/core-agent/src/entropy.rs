/// Shannon entropy calculation and obfuscation analysis.
///
/// Used to detect encoded or obfuscated payloads in script files — a hallmark
/// of malware that tries to evade signature detection by encoding its payload
/// in base64, hex shellcode, or other encoding schemes.
///
/// MITRE T1027 — Obfuscated Files or Information

/// Compute Shannon entropy of a byte slice.
/// Range: 0.0 (all bytes the same) to 8.0 (perfectly random / compressed / encrypted).
/// Typical ranges:
///   English text:          3.5 – 5.0
///   Source code:           4.5 – 6.0
///   Base64-encoded data:   5.8 – 6.2
///   Encrypted/compressed:  7.0 – 8.0
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone)]
pub struct ObfuscationResult {
    pub entropy: f64,
    pub has_base64_blob: bool,
    pub has_hex_shellcode: bool,
    pub has_eval_dynamic: bool,
    pub suspicion_score: u32,
}

/// Analyse file content for obfuscation indicators.
///
/// Designed to run on the first 4 KB of script files (.sh, .py, .js, etc.)
/// encountered in monitored directories. If `suspicion_score >= 20`, the caller
/// should emit `alert_obfuscated_content_detected`.
pub fn analyze_obfuscation(content: &[u8]) -> ObfuscationResult {
    let entropy = shannon_entropy(content);
    let text = String::from_utf8_lossy(content);

    let has_base64_blob = has_long_base64_run(&text, 64);
    let has_hex_shellcode = has_hex_shellcode_pattern(&text);
    let has_eval_dynamic = has_eval_dynamic_pattern(&text);

    let mut score = 0u32;
    if entropy > 7.2 {
        score += 25; // Very high entropy — compressed/encrypted
    } else if entropy > 6.5 {
        score += 12; // High entropy — likely encoded
    }
    if has_base64_blob {
        score += 15;
    }
    if has_hex_shellcode {
        score += 20;
    }
    if has_eval_dynamic {
        score += 15;
    }

    ObfuscationResult {
        entropy,
        has_base64_blob,
        has_hex_shellcode,
        has_eval_dynamic,
        suspicion_score: score,
    }
}

/// Return true if `text` contains a run of at least `min_len` consecutive
/// characters that are all valid base64 alphabet members [A-Za-z0-9+/=].
///
/// We use 64 characters as the threshold to avoid false positives from:
/// - Short base64 constants in source code
/// - URL path components
/// - Short encoded config values
///
/// 64 consecutive base64 chars = ~48 bytes of encoded data — the minimum
/// size of any meaningful encoded payload.
fn has_long_base64_run(text: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Return true if `text` contains 8 or more consecutive `\xNN` escape sequences
/// — the standard notation for shellcode in Python/Ruby/Perl scripts.
fn has_hex_shellcode_pattern(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut consecutive = 0usize;
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'\\'
            && bytes[i + 1] == b'x'
            && bytes[i + 2].is_ascii_hexdigit()
            && bytes[i + 3].is_ascii_hexdigit()
        {
            consecutive += 1;
            if consecutive >= 8 {
                return true;
            }
            i += 4;
        } else {
            consecutive = 0;
            i += 1;
        }
    }
    false
}

/// Return true if `text` contains patterns consistent with dynamic code execution:
/// `eval(`, `exec(` combined with decode/base64, or `__import__` with base64.
fn has_eval_dynamic_pattern(text: &str) -> bool {
    // eval( — direct eval of a dynamic expression
    if text.contains("eval(") || text.contains("eval (") {
        return true;
    }
    // exec( combined with decode or base64 — fetching and decoding a payload
    if (text.contains("exec(") || text.contains("exec ("))
        && (text.contains(".decode") || text.contains("base64"))
    {
        return true;
    }
    // __import__('base64') — Python base64 import without explicit import statement
    if text.contains("__import__") && text.contains("base64") {
        return true;
    }
    // execute(response...) — fetching remote payload and executing it
    if text.contains("exec(response") || text.contains("exec(requests") {
        return true;
    }
    false
}

/// Return true if the given file extension is a script type we should analyse.
pub fn is_script_extension(ext: &str) -> bool {
    matches!(ext, "sh" | "py" | "js" | "rb" | "pl" | "php" | "bash" | "zsh" | "ts" | "mjs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_high_for_random_bytes() {
        // Random-looking data should have entropy close to 8.0
        let data: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.0, "random bytes should have entropy > 7.0, got {e}");
    }

    #[test]
    fn entropy_low_for_english_text() {
        let text = b"The quick brown fox jumps over the lazy dog. This is a normal English sentence that should have moderate entropy.";
        let e = shannon_entropy(text);
        assert!(e < 5.5, "English text should have entropy < 5.5, got {e}");
    }

    #[test]
    fn entropy_zero_for_uniform_bytes() {
        let data = vec![0xABu8; 1024];
        let e = shannon_entropy(&data);
        assert_eq!(e, 0.0, "uniform bytes should have entropy 0.0");
    }

    #[test]
    fn base64_blob_detected() {
        // 80 chars of pure base64 — well over threshold
        let content = b"#!/bin/sh\nDATA=SGVsbG9Xb3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZGhlbGxvd29ybGQ=\n";
        let result = analyze_obfuscation(content);
        assert!(result.has_base64_blob, "should detect 80-char base64 blob");
    }

    #[test]
    fn hex_shellcode_detected() {
        let content = b"\\x48\\x65\\x6c\\x6c\\x6f\\x57\\x6f\\x72\\x6c\\x64";
        let result = analyze_obfuscation(content);
        assert!(result.has_hex_shellcode, "should detect \\xNN shellcode sequence");
    }

    #[test]
    fn eval_dynamic_detected() {
        let content = b"import base64\nexec(__import__('base64').b64decode('SGVsbG8='))";
        let result = analyze_obfuscation(content);
        assert!(result.has_eval_dynamic, "should detect __import__ + base64 pattern");
    }

    #[test]
    fn legitimate_shell_script_low_suspicion() {
        let content = b"#!/bin/bash\nset -e\necho 'Starting backup...'\nrsync -av ~/Documents /Volumes/Backup/\necho 'Done'";
        let result = analyze_obfuscation(content);
        assert!(
            result.suspicion_score < 20,
            "legitimate shell script should score < 20, got {}",
            result.suspicion_score
        );
    }

    #[test]
    fn legitimate_python_script_low_suspicion() {
        let content = b"#!/usr/bin/env python3\nimport os\nimport sys\n\ndef main():\n    files = os.listdir('.')\n    for f in files:\n        print(f)\n\nif __name__ == '__main__':\n    main()";
        let result = analyze_obfuscation(content);
        assert!(
            result.suspicion_score < 20,
            "legitimate python script should score < 20, got {}",
            result.suspicion_score
        );
    }
}
