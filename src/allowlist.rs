/// Command allowlist management.
///
/// The allowlist is pinned at compile time — there is no runtime override.
/// This eliminates the attack surface of an agent widening its own permissions.
use std::collections::HashSet;

const DEFAULT_ALLOWLIST: &[&str] = &[
    // Search
    "grep", "rg", "ugrep", // Find files
    "find", "fd", // Read files
    "cat", "bat", "head", "tail", // List/inspect
    "ls", "eza", "tree", "stat", "file", "du", "wc", "pwd", "which",
    // Text processing (read-only)
    "sort", "uniq", "cut", "tr", "diff", "comm", // Path utilities
    "basename", "dirname", "realpath", // Misc
    "echo", "printf", "date", "true", "false", "test", "printenv",
];

/// Environment variables forwarded to child processes for correct operation.
/// These are NOT available for use in command arguments — they're only passed
/// through to the spawned process environment. The only variables allowed in
/// arguments are for-loop variables, which the validator approves dynamically.
pub const FORWARDED_VARS: &[&str] = &[
    "HOME", "USER", "PATH", "PWD", "LANG", "TERM", "SHELL", "TMPDIR",
];

#[derive(Debug, Clone)]
pub struct Allowlist {
    commands: HashSet<String>,
}

impl Allowlist {
    /// Build the allowlist from the pinned defaults.
    pub fn new() -> Self {
        let commands: HashSet<String> =
            DEFAULT_ALLOWLIST.iter().map(|s| s.to_string()).collect();
        Self { commands }
    }

    /// Check if a command is allowed.
    /// Rejects any command containing path separators or starting with '.'.
    pub fn is_allowed(&self, cmd: &str) -> bool {
        if cmd.contains('/') || cmd.contains('\\') || cmd.starts_with('.') {
            return false;
        }
        self.commands.contains(cmd)
    }

    /// Get all allowed commands (for error messages).
    pub fn allowed_commands(&self) -> Vec<&str> {
        let mut cmds: Vec<&str> = self.commands.iter().map(|s| s.as_str()).collect();
        cmds.sort();
        cmds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_allowlist() {
        let al = Allowlist::new();
        assert!(al.is_allowed("grep"));
        assert!(al.is_allowed("ls"));
        assert!(!al.is_allowed("curl"));
    }

    #[test]
    fn test_path_rejected() {
        let al = Allowlist::new();
        assert!(!al.is_allowed("/usr/bin/grep"));
        assert!(!al.is_allowed("./grep"));
        assert!(!al.is_allowed("..\\grep"));
        assert!(!al.is_allowed(".hidden"));
    }
}
