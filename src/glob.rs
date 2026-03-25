/// Glob expansion scoped to a working directory.
use std::path::Path;

/// Returns true if a string contains unescaped glob metacharacters.
pub fn is_glob(s: &str) -> bool {
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                chars.next();
            } // skip escaped char
            '*' | '?' | '[' => return true,
            _ => {}
        }
    }
    false
}

/// Expand a glob pattern relative to the working directory.
/// Absolute patterns and path traversal are always rejected.
pub fn expand_glob(pattern: &str, working_dir: &Path) -> Result<Vec<String>, String> {
    if pattern.starts_with('/') {
        return Err(format!("absolute glob pattern '{}' not allowed", pattern));
    }

    // Reject patterns with .. path traversal
    if pattern.split('/').any(|seg| seg == "..") {
        return Err(format!(
            "glob pattern '{}' contains path traversal (..)",
            pattern
        ));
    }

    let full_pattern = working_dir.join(pattern);

    let pattern_str = full_pattern
        .to_str()
        .ok_or("invalid UTF-8 in glob pattern")?;

    let entries = glob::glob(pattern_str)
        .map_err(|e| format!("invalid glob pattern '{}': {}", pattern, e))?;

    let canon_working = working_dir
        .canonicalize()
        .map_err(|e| format!("cannot canonicalize working dir: {}", e))?;

    let mut results = Vec::new();
    for entry in entries {
        match entry {
            Ok(path) => {
                // Verify the path stays within working_dir
                match path.canonicalize() {
                    Ok(canon_path) => {
                        if !canon_path.starts_with(&canon_working) {
                            continue; // skip paths outside working_dir
                        }
                    }
                    Err(_) => continue, // skip paths that can't be verified (broken symlinks, etc.)
                }
                // Convert back to relative path
                let display_path = path
                    .strip_prefix(working_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                results.push(display_path);
            }
            Err(e) => {
                // Skip unreadable entries
                eprintln!("glob warning: {}", e);
            }
        }
    }

    // If no matches, return the original pattern (shell behavior)
    if results.is_empty() {
        results.push(pattern.to_string());
    }

    results.sort();
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_glob() {
        assert!(is_glob("*.rs"));
        assert!(is_glob("src/**/*.rs"));
        assert!(is_glob("file[0-9].txt"));
        assert!(is_glob("test?.log"));
        assert!(!is_glob("hello.rs"));
        assert!(!is_glob("path/to/file"));
        assert!(!is_glob("escaped\\*star"));
    }

    #[test]
    fn test_expand_no_absolute() {
        let result = expand_glob("/etc/*", Path::new("/tmp"));
        assert!(result.is_err());
    }
}
