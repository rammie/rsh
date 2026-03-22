/// Command allowlist management.
///
/// Sources (in priority order, last wins):
/// 1. Built-in defaults
/// 2. Config file (~/.rsh/allowlist)
/// 3. Environment variable RSH_ALLOWLIST
/// 4. CLI flag --allow

use std::collections::HashSet;
use std::path::PathBuf;

const DEFAULT_ALLOWLIST: &[&str] = &[
    // Search
    "grep", "rg", "ugrep",
    // Find files
    "find", "fd",
    // Read files
    "cat", "bat", "head", "tail", "less",
    // List/inspect
    "ls", "eza", "stat", "file", "du", "wc", "pwd", "which",
    // Text processing (read-only — sed -i is blocked separately)
    "sort", "uniq", "cut", "tr", "sed", "diff", "comm",
    // Path utilities
    "basename", "dirname", "realpath",
    // Misc
    "echo", "date", "true", "false", "test",
];

/// Environment variables approved for use in command arguments and expansion.
pub const APPROVED_VARS: &[&str] = &[
    "HOME", "USER", "PATH", "PWD", "LANG", "TERM", "SHELL", "EDITOR", "PAGER", "TMPDIR",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
];

#[derive(Debug, Clone)]
pub struct Allowlist {
    commands: HashSet<String>,
}

impl Allowlist {
    /// Build the allowlist from all sources.
    pub fn load(cli_allow: Option<&str>) -> Self {
        let mut commands: HashSet<String> = DEFAULT_ALLOWLIST.iter().map(|s| s.to_string()).collect();

        // Load from config file
        if let Some(config) = Self::load_config_file() {
            commands = config;
        }

        // Override with env var
        if let Ok(env_val) = std::env::var("RSH_ALLOWLIST") {
            commands = env_val.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Override with CLI flag
        if let Some(allow_str) = cli_allow {
            commands = allow_str.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        Self { commands }
    }

    fn load_config_file() -> Option<HashSet<String>> {
        let path = dirs_config_path()?;
        let content = std::fs::read_to_string(path).ok()?;
        let commands: HashSet<String> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_string())
            .collect();
        if commands.is_empty() {
            None
        } else {
            Some(commands)
        }
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

fn dirs_config_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let path = PathBuf::from(home).join(".rsh").join("allowlist");
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_allowlist() {
        // Clear env to ensure defaults
        std::env::remove_var("RSH_ALLOWLIST");
        let al = Allowlist::load(None);
        assert!(al.is_allowed("grep"));
        assert!(al.is_allowed("ls"));
        assert!(!al.is_allowed("curl"));
        assert!(!al.is_allowed("rm"));
    }

    #[test]
    fn test_cli_override() {
        let al = Allowlist::load(Some("curl,wget"));
        assert!(al.is_allowed("curl"));
        assert!(al.is_allowed("wget"));
        assert!(!al.is_allowed("grep"));
    }

    #[test]
    fn test_path_rejected() {
        std::env::remove_var("RSH_ALLOWLIST");
        let al = Allowlist::load(None);
        assert!(!al.is_allowed("/usr/bin/grep"));
        assert!(!al.is_allowed("./grep"));
        assert!(!al.is_allowed("..\\grep"));
        assert!(!al.is_allowed(".hidden"));
    }
}
