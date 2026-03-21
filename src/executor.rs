/// Executor: walks the AST, wires pipes, and spawns processes.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::allowlist::Allowlist;
use crate::ast::{self, Arg, Pipeline, Program, RedirectKind};
use crate::glob as rsh_glob;

/// The result of executing a program.
fn is_false(v: &bool) -> bool {
    !v
}

/// Extract variable names referenced in a double-quoted string ($VAR or ${VAR}).
fn extract_var_names(s: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            let mut name = String::new();
            if chars.peek() == Some(&'{') {
                chars.next();
                while let Some(&c) = chars.peek() {
                    if c == '}' {
                        chars.next();
                        break;
                    }
                    name.push(c);
                    chars.next();
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            if !name.is_empty() {
                vars.push(name);
            }
        }
    }
    vars
}

/// Wait for a child process with a deadline. Kills the child if the deadline passes.
fn wait_with_deadline(
    mut child: std::process::Child,
    deadline: Instant,
) -> Result<std::process::Output, String> {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child.wait_with_output()
                    .map_err(|e| format!("failed to read output: {}", e));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("command timed out".to_string());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("error waiting for process: {}", e)),
        }
    }
}

/// Snap a byte-index down to the nearest UTF-8 char boundary (<= pos).
fn floor_char_boundary(s: &str, pos: usize) -> usize {
    if pos >= s.len() {
        return s.len();
    }
    let mut i = pos;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[derive(Debug, serde::Serialize)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub commands: Vec<String>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
}

impl Output {
    pub fn error(msg: String) -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
            commands: Vec::new(),
            error: Some(msg),
            truncated: false,
        }
    }
}

/// Arguments that allow commands to execute arbitrary sub-commands or perform
/// destructive actions, bypassing all rsh restrictions. Keyed by command name.
const DANGEROUS_ARGS: &[(&str, &[&str])] = &[
    ("find", &["-exec", "-execdir", "-ok", "-okdir", "-delete"]),
    ("fd", &["-x", "--exec", "-X", "--exec-batch"]),
    ("xargs", &[]),  // xargs itself is the danger — always runs sub-commands
];

/// Approved environment variables that can be referenced.
const APPROVED_VARS: &[&str] = &[
    "HOME", "USER", "PATH", "PWD", "LANG", "TERM",
    "SHELL", "EDITOR", "PAGER", "TMPDIR", "XDG_CONFIG_HOME",
    "XDG_DATA_HOME", "XDG_CACHE_HOME",
];

pub struct Executor {
    allowlist: Allowlist,
    working_dir: std::path::PathBuf,
    allow_absolute: bool,
    allow_redirects: bool,
    max_output: usize,
    timeout: std::time::Duration,
    inherit_env: bool,
    approved_vars: HashSet<String>,
}

impl Executor {
    pub fn new(
        allowlist: Allowlist,
        working_dir: std::path::PathBuf,
        allow_absolute: bool,
        allow_redirects: bool,
        max_output: usize,
        timeout_secs: u64,
        inherit_env: bool,
    ) -> Self {
        let approved_vars: HashSet<String> = APPROVED_VARS.iter().map(|s| s.to_string()).collect();
        Self {
            allowlist,
            working_dir,
            allow_absolute,
            allow_redirects,
            max_output,
            timeout: std::time::Duration::from_secs(timeout_secs),
            inherit_env,
            approved_vars,
        }
    }

    /// Configure environment variables on a Command builder.
    fn configure_env(&self, process: &mut Command) {
        if !self.inherit_env {
            process.env_clear();
            for var in &self.approved_vars {
                if let Ok(val) = std::env::var(var) {
                    process.env(var, val);
                }
            }
        }
    }

    /// Validate the program before execution. Returns all command names and any error.
    fn validate(&self, program: &Program) -> Result<Vec<String>, String> {
        let mut command_names = Vec::new();
        for pipeline in &program.pipelines {
            let last_idx = pipeline.commands.len() - 1;
            for (cmd_idx, cmd) in pipeline.commands.iter().enumerate() {
                command_names.push(cmd.name.clone());
                if !self.allowlist.is_allowed(&cmd.name) {
                    return Err(format!(
                        "command '{}' not in allowlist (allowed: {})",
                        cmd.name,
                        self.allowlist.allowed_commands().join(", ")
                    ));
                }
                // Check for dangerous sub-command arguments
                for (dangerous_cmd, dangerous_flags) in DANGEROUS_ARGS {
                    if cmd.name == *dangerous_cmd {
                        // If the flag list is empty, the command itself is always dangerous
                        if dangerous_flags.is_empty() {
                            return Err(format!(
                                "'{}' executes arbitrary commands and is not allowed",
                                cmd.name
                            ));
                        }
                        for arg in &cmd.args {
                            let val = match arg {
                                Arg::Bare(s) | Arg::SingleQuoted(s) | Arg::DoubleQuoted(s) => s.as_str(),
                                Arg::Var(_) => continue,
                            };
                            if dangerous_flags.contains(&val) {
                                return Err(format!(
                                    "'{}' flag on '{}' executes arbitrary commands and is not allowed",
                                    val, cmd.name
                                ));
                            }
                        }
                    }
                }
                // Validate redirects are allowed
                if !cmd.redirects.is_empty() && !self.allow_redirects {
                    return Err(
                        "redirects are not allowed (use --allow-redirects to enable)".to_string()
                    );
                }
                if !cmd.redirects.is_empty() && cmd_idx < last_idx {
                    return Err(format!(
                        "redirects on non-final pipeline command '{}' are not supported",
                        cmd.name
                    ));
                }
                // Validate variable references
                for arg in &cmd.args {
                    match arg {
                        Arg::Var(name) => {
                            if !self.approved_vars.contains(name.as_str()) {
                                return Err(format!(
                                    "variable '{}' not in approved list (approved: {})",
                                    name,
                                    APPROVED_VARS.join(", ")
                                ));
                            }
                        }
                        Arg::DoubleQuoted(s) => {
                            for var_name in extract_var_names(s) {
                                if !self.approved_vars.contains(var_name.as_str()) {
                                    return Err(format!(
                                        "variable '{}' not in approved list (approved: {})",
                                        var_name,
                                        APPROVED_VARS.join(", ")
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(command_names)
    }

    /// Expand an argument into one or more string values.
    fn expand_arg(&self, arg: &Arg) -> Result<Vec<String>, String> {
        match arg {
            Arg::Bare(s) => {
                if rsh_glob::is_glob(s) {
                    rsh_glob::expand_glob(s, &self.working_dir, self.allow_absolute)
                } else {
                    Ok(vec![s.clone()])
                }
            }
            Arg::SingleQuoted(s) => Ok(vec![s.clone()]),
            Arg::DoubleQuoted(s) => {
                // For double-quoted strings, expand embedded $VAR references
                Ok(vec![self.expand_vars_in_string(s)?])
            }
            Arg::Var(name) => {
                if !self.approved_vars.contains(name.as_str()) {
                    return Err(format!("variable '{}' not in approved list", name));
                }
                Ok(vec![std::env::var(name).unwrap_or_default()])
            }
        }
    }

    fn expand_vars_in_string(&self, s: &str) -> Result<String, String> {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '$' {
                let mut var_name = String::new();
                if chars.peek() == Some(&'{') {
                    chars.next(); // consume {
                    while let Some(&c) = chars.peek() {
                        if c == '}' {
                            chars.next();
                            break;
                        }
                        var_name.push(c);
                        chars.next();
                    }
                } else {
                    while let Some(&c) = chars.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            var_name.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                if !var_name.is_empty() {
                    if !self.approved_vars.contains(var_name.as_str()) {
                        return Err(format!("variable '{}' not in approved list", var_name));
                    }
                    result.push_str(&std::env::var(&var_name).unwrap_or_default());
                } else {
                    result.push('$');
                }
            } else {
                result.push(ch);
            }
        }
        Ok(result)
    }

    /// Execute a full program.
    pub fn execute(&self, program: &Program) -> Output {
        let command_names = match self.validate(program) {
            Ok(names) => names,
            Err(e) => return Output::error(e),
        };

        let mut all_stdout = String::new();
        let mut all_stderr = String::new();
        let mut last_exit_code = 0;

        for pipeline in &program.pipelines {
            match self.execute_pipeline(pipeline) {
                Ok((stdout, stderr, code)) => {
                    all_stdout.push_str(&stdout);
                    all_stderr.push_str(&stderr);
                    last_exit_code = code;
                }
                Err(e) => {
                    return Output {
                        stdout: all_stdout,
                        stderr: all_stderr,
                        exit_code: 1,
                        commands: command_names,
                        error: Some(e),
                        truncated: false,
                    };
                }
            }
        }

        let mut truncated = false;
        let total = all_stdout.len() + all_stderr.len();
        if self.max_output > 0 && total > self.max_output {
            truncated = true;
            // Truncate proportionally
            let stdout_limit = (self.max_output as f64 * (all_stdout.len() as f64 / total as f64)) as usize;
            let stderr_limit = self.max_output.saturating_sub(stdout_limit);
            all_stdout.truncate(floor_char_boundary(&all_stdout, stdout_limit));
            all_stderr.truncate(floor_char_boundary(&all_stderr, stderr_limit));
        }

        Output {
            stdout: all_stdout,
            stderr: all_stderr,
            exit_code: last_exit_code,
            commands: command_names,
            error: None,
            truncated,
        }
    }

    fn execute_pipeline(&self, pipeline: &Pipeline) -> Result<(String, String, i32), String> {
        let commands = &pipeline.commands;

        if commands.len() == 1 {
            return self.execute_single_command(&commands[0]);
        }

        // Multi-command pipeline: wire stdout -> stdin via pipes
        let mut previous_stdout: Option<os_pipe::PipeReader> = None;
        let mut child_processes = Vec::new();
        let last_idx = commands.len() - 1;

        for (i, cmd) in commands.iter().enumerate() {
            let expanded_args = self.expand_command_args(cmd)?;
            let mut process = Command::new(&cmd.name);
            process.args(&expanded_args);
            process.current_dir(&self.working_dir);
            self.configure_env(&mut process);

            // Wire stdin from previous pipe
            if let Some(prev_out) = previous_stdout.take() {
                process.stdin(prev_out);
            }

            if i < last_idx {
                // Create a pipe for stdout
                let (reader, writer) = os_pipe::pipe()
                    .map_err(|e| format!("failed to create pipe: {}", e))?;
                process.stdout(writer);
                process.stderr(Stdio::piped());
                let child = process.spawn()
                    .map_err(|e| format!("failed to spawn '{}': {}", cmd.name, e))?;
                child_processes.push(child);
                previous_stdout = Some(reader);
            } else {
                // Last command: capture stdout and handle redirects
                process.stdout(Stdio::piped());
                process.stderr(Stdio::piped());
                let child = process.spawn()
                    .map_err(|e| format!("failed to spawn '{}': {}", cmd.name, e))?;
                child_processes.push(child);
            }
        }

        // Collect output from all children with shared deadline
        let deadline = Instant::now() + self.timeout;
        let mut all_stderr = String::new();
        let last = child_processes.len() - 1;
        let mut final_stdout = String::new();
        let mut final_exit_code = 0;

        for (i, child) in child_processes.into_iter().enumerate() {
            let output = match wait_with_deadline(child, deadline) {
                Ok(o) => o,
                Err(e) => {
                    // On timeout, remaining children are already gone (moved into iterator)
                    return Err(e);
                }
            };

            all_stderr.push_str(&String::from_utf8_lossy(&output.stderr));

            if i == last {
                final_stdout = String::from_utf8_lossy(&output.stdout).to_string();
                final_exit_code = output.status.code().unwrap_or(1);

                // Handle redirects on last command
                let last_cmd = &commands[last];
                if !last_cmd.redirects.is_empty() {
                    final_stdout = self.apply_redirects(&final_stdout, &last_cmd.redirects)?;
                }
            }
        }

        Ok((final_stdout, all_stderr, final_exit_code))
    }

    fn expand_command_args(&self, cmd: &ast::Command) -> Result<Vec<String>, String> {
        let mut expanded = Vec::new();
        for arg in &cmd.args {
            // Check path traversal on user-supplied arguments (not variable expansions)
            match arg {
                Arg::Bare(s) => self.check_arg_path(s)?,
                Arg::SingleQuoted(s) => self.check_arg_path(s)?,
                Arg::DoubleQuoted(_) | Arg::Var(_) => {} // checked at validate time / trusted
            }
            expanded.extend(self.expand_arg(arg)?);
        }
        Ok(expanded)
    }

    /// Reject arguments that traverse outside the working directory.
    fn check_arg_path(&self, arg: &str) -> Result<(), String> {
        // Skip flags
        if arg.starts_with('-') {
            return Ok(());
        }
        // Reject absolute paths unless allowed
        if arg.starts_with('/') && !self.allow_absolute {
            return Err(format!(
                "absolute path '{}' in argument not allowed (use --allow-absolute)",
                arg
            ));
        }
        // Reject .. path components
        if arg.split('/').any(|seg| seg == "..") {
            return Err(format!(
                "path traversal ('..') in argument '{}' not allowed",
                arg
            ));
        }
        Ok(())
    }

    fn execute_single_command(
        &self,
        cmd: &ast::Command,
    ) -> Result<(String, String, i32), String> {
        let expanded_args = self.expand_command_args(cmd)?;

        let mut process = Command::new(&cmd.name);
        process.args(&expanded_args);
        process.current_dir(&self.working_dir);
        self.configure_env(&mut process);
        process.stdout(Stdio::piped());
        process.stderr(Stdio::piped());

        let child = process.spawn()
            .map_err(|e| format!("failed to spawn '{}': {}", cmd.name, e))?;

        let deadline = Instant::now() + self.timeout;
        let output = wait_with_deadline(child, deadline)?;

        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(1);

        // Handle redirects
        if !cmd.redirects.is_empty() {
            stdout = self.apply_redirects(&stdout, &cmd.redirects)?;
        }

        Ok((stdout, stderr, exit_code))
    }

    fn apply_redirects(&self, stdout: &str, redirects: &[ast::Redirect]) -> Result<String, String> {
        for redirect in redirects {
            let path = if redirect.target.starts_with('/') {
                if !self.allow_absolute {
                    return Err(format!(
                        "absolute redirect path '{}' not allowed (use --allow-absolute)",
                        redirect.target
                    ));
                }
                std::path::PathBuf::from(&redirect.target)
            } else {
                self.working_dir.join(&redirect.target)
            };

            // Path traversal guard: ensure the resolved path stays within working_dir.
            // We canonicalize the parent directory (which must exist) and check the prefix.
            let canon_working = self.working_dir.canonicalize()
                .map_err(|e| format!("cannot canonicalize working dir: {}", e))?;
            let parent = path.parent().unwrap_or(&path);
            // Create parent dir if it doesn't exist (only within working_dir)
            let canon_parent = if parent.exists() {
                parent.canonicalize()
                    .map_err(|e| format!("cannot canonicalize redirect parent: {}", e))?
            } else {
                return Err(format!(
                    "redirect path '{}' escapes working directory",
                    redirect.target
                ));
            };
            let full_canon = canon_parent.join(path.file_name().unwrap_or_default());
            if !full_canon.starts_with(&canon_working) {
                return Err(format!(
                    "redirect path '{}' escapes working directory",
                    redirect.target
                ));
            }

            match redirect.kind {
                RedirectKind::Overwrite => {
                    let mut f = File::create(&path)
                        .map_err(|e| format!("cannot open '{}' for writing: {}", redirect.target, e))?;
                    f.write_all(stdout.as_bytes())
                        .map_err(|e| format!("write error: {}", e))?;
                }
                RedirectKind::Append => {
                    let mut f = OpenOptions::new().create(true).append(true).open(&path)
                        .map_err(|e| format!("cannot open '{}' for appending: {}", redirect.target, e))?;
                    f.write_all(stdout.as_bytes())
                        .map_err(|e| format!("write error: {}", e))?;
                }
            }
        }
        // When stdout is redirected, the captured output goes to the file, not to the caller
        Ok(String::new())
    }
}
