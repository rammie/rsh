/// Executor: walks the brush-parser AST, expands words, wires pipes, and spawns processes.
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Command, Stdio};

use brush_parser::ast::*;
use brush_parser::word::{self, Parameter, ParameterExpr, WordPiece};
use brush_parser::ParserOptions;

use crate::allowlist::{self, Allowlist};
use crate::glob as rsh_glob;
use crate::validator::{self, ValidatorConfig};

/// Extract exit code from a process status, mapping signal death to 128 + signal (bash convention).
fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(1)
}

/// Ignore SIGINT in the current process (children still receive it from the terminal).
/// This matches bash behavior: the shell waits for the child to finish, then checks its exit status.
fn ignore_sigint() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
}

/// Restore default SIGINT handling.
fn restore_sigint() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
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

pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl Output {
    pub fn error(msg: String) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("rsh: {}\n", msg),
            exit_code: 1,
        }
    }
}

/// Maximum iterations for any loop (for, while, until).
const MAX_LOOP_ITERATIONS: usize = 10_000;

pub struct Executor {
    allowlist: Allowlist,
    working_dir: std::path::PathBuf,
    allow_redirects: bool,
    max_output: usize,
    inherit_env: bool,
}

impl Executor {
    pub fn new(
        allowlist: Allowlist,
        working_dir: std::path::PathBuf,
        allow_redirects: bool,
        max_output: usize,
        inherit_env: bool,
    ) -> Self {
        Self {
            allowlist,
            working_dir,
            allow_redirects,
            max_output,
            inherit_env,
        }
    }

    /// Execute a validated brush-parser Program.
    pub fn execute(&self, program: &Program) -> Output {
        // Validate first
        let config = ValidatorConfig {
            allow_redirects: self.allow_redirects,
        };
        if let Err(e) = validator::validate(program, &self.allowlist, &config) {
            return Output::error(e);
        }

        // Ignore SIGINT while children run (bash behavior: the shell waits for
        // the child to finish, then inspects its exit status).
        ignore_sigint();

        let mut local_vars: HashMap<String, String> = HashMap::new();
        let (mut all_stdout, mut all_stderr, last_exit_code) =
            match self.execute_program(program, &mut local_vars) {
                Ok(result) => result,
                Err(e) => {
                    restore_sigint();
                    return Output {
                        stdout: String::new(),
                        stderr: format!("rsh: {}\n", e),
                        exit_code: 1,
                    };
                }
            };

        // Truncate if needed
        let total = all_stdout.len() + all_stderr.len();
        if self.max_output > 0 && total > self.max_output {
            let stdout_limit =
                (self.max_output as f64 * (all_stdout.len() as f64 / total as f64)) as usize;
            let stderr_limit = self.max_output.saturating_sub(stdout_limit);
            all_stdout.truncate(floor_char_boundary(&all_stdout, stdout_limit));
            all_stderr.truncate(floor_char_boundary(&all_stderr, stderr_limit));
            all_stderr.push_str("rsh: output truncated (exceeded limit)\n");
        }

        restore_sigint();

        Output {
            stdout: all_stdout,
            stderr: all_stderr,
            exit_code: last_exit_code,
        }
    }

    // --- Execution tree ---

    fn execute_program(
        &self,
        program: &Program,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let mut all_stdout = String::new();
        let mut all_stderr = String::new();
        let mut last_exit_code = 0;

        for complete_command in &program.complete_commands {
            let (stdout, stderr, code) =
                self.execute_compound_list(complete_command, local_vars)?;
            all_stdout.push_str(&stdout);
            all_stderr.push_str(&stderr);
            last_exit_code = code;
        }

        Ok((all_stdout, all_stderr, last_exit_code))
    }

    fn execute_compound_list(
        &self,
        list: &CompoundList,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let mut all_stdout = String::new();
        let mut all_stderr = String::new();
        let mut last_exit_code = 0;

        for item in &list.0 {
            let (stdout, stderr, code) = self.execute_and_or_list(&item.0, local_vars)?;
            all_stdout.push_str(&stdout);
            all_stderr.push_str(&stderr);
            last_exit_code = code;
            local_vars.insert("?".to_string(), code.to_string());
        }

        Ok((all_stdout, all_stderr, last_exit_code))
    }

    fn execute_and_or_list(
        &self,
        and_or: &AndOrList,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let mut all_stdout = String::new();
        let mut all_stderr = String::new();

        let (stdout, stderr, mut last_code) = self.execute_pipeline(&and_or.first, local_vars)?;
        all_stdout.push_str(&stdout);
        all_stderr.push_str(&stderr);
        local_vars.insert("?".to_string(), last_code.to_string());

        for additional in &and_or.additional {
            match additional {
                AndOr::And(pipeline) => {
                    if last_code == 0 {
                        let (stdout, stderr, code) = self.execute_pipeline(pipeline, local_vars)?;
                        all_stdout.push_str(&stdout);
                        all_stderr.push_str(&stderr);
                        last_code = code;
                        local_vars.insert("?".to_string(), last_code.to_string());
                    }
                }
                AndOr::Or(pipeline) => {
                    if last_code != 0 {
                        let (stdout, stderr, code) = self.execute_pipeline(pipeline, local_vars)?;
                        all_stdout.push_str(&stdout);
                        all_stderr.push_str(&stderr);
                        last_code = code;
                        local_vars.insert("?".to_string(), last_code.to_string());
                    }
                }
            }
        }

        Ok((all_stdout, all_stderr, last_code))
    }

    fn execute_pipeline(
        &self,
        pipeline: &Pipeline,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let commands = &pipeline.seq;

        if commands.len() == 1 {
            let (stdout, stderr, mut code) =
                self.execute_command(&commands[0], local_vars, None)?;
            if pipeline.bang {
                code = if code == 0 { 1 } else { 0 };
            }
            return Ok((stdout, stderr, code));
        }

        // Multi-command pipeline: use OS pipes for concurrent execution.
        // All commands in a pipeline must be simple commands for OS pipe wiring.
        // If any are compound, fall back to sequential execution.

        let all_simple = commands
            .iter()
            .all(|c| matches!(c, BrushCommand::Simple(_)));

        if all_simple {
            return self.execute_simple_pipeline(commands, local_vars, pipeline.bang);
        }

        // Fallback: sequential execution for mixed pipelines
        let mut previous_stdout_data: Option<String> = None;
        let mut all_stderr = String::new();
        let mut final_stdout = String::new();
        let mut final_exit_code = 0;

        for (i, cmd) in commands.iter().enumerate() {
            let is_last = i == commands.len() - 1;
            let (stdout, stderr, code) =
                self.execute_command(cmd, local_vars, previous_stdout_data.take())?;
            all_stderr.push_str(&stderr);

            if is_last {
                final_stdout = stdout;
                final_exit_code = code;
            } else {
                previous_stdout_data = Some(stdout);
                final_exit_code = code;
            }
        }

        if pipeline.bang {
            final_exit_code = if final_exit_code == 0 { 1 } else { 0 };
        }

        Ok((final_stdout, all_stderr, final_exit_code))
    }

    /// Execute a pipeline of simple commands using OS pipes for concurrent execution.
    fn execute_simple_pipeline(
        &self,
        commands: &[BrushCommand],
        local_vars: &mut HashMap<String, String>,
        bang: bool,
    ) -> Result<(String, String, i32), String> {
        let mut previous_stdout: Option<os_pipe::PipeReader> = None;
        let mut child_processes = Vec::new();
        let mut cmd_infos = Vec::new(); // track redirects per command
        let last_idx = commands.len() - 1;

        for (i, cmd) in commands.iter().enumerate() {
            let simple = match cmd {
                BrushCommand::Simple(s) => s,
                _ => unreachable!(),
            };
            let (name, args, redirects, stderr_behavior) =
                self.extract_simple_command(simple, local_vars)?;

            let mut process = Command::new(&name);
            process.args(&args);
            process.current_dir(&self.working_dir);
            self.configure_env(&mut process);

            // Wire stdin from previous pipe
            if let Some(prev_out) = previous_stdout.take() {
                process.stdin(prev_out);
            }

            if i < last_idx {
                let (reader, writer) =
                    os_pipe::pipe().map_err(|e| format!("failed to create pipe: {}", e))?;
                // Compute stderr Stdio before stdout consumes the writer
                let stderr_stdio = match stderr_behavior {
                    StderrBehavior::DevNull => Stdio::null(),
                    StderrBehavior::MergeToStdout => {
                        // 2>&1: clone the pipe writer so stderr goes to the same pipe
                        Stdio::from(
                            writer
                                .try_clone()
                                .map_err(|e| format!("failed to clone pipe: {}", e))?,
                        )
                    }
                    StderrBehavior::Capture => Stdio::piped(),
                };
                process.stdout(writer);
                process.stderr(stderr_stdio);
                let child = process
                    .spawn()
                    .map_err(|e| format!("failed to spawn '{}': {}", name, e))?;
                child_processes.push(child);
                cmd_infos.push(redirects);
                previous_stdout = Some(reader);
            } else {
                process.stdout(Stdio::piped());
                process.stderr(Stdio::piped());
                let child = process
                    .spawn()
                    .map_err(|e| format!("failed to spawn '{}': {}", name, e))?;
                child_processes.push(child);
                cmd_infos.push(redirects);
            }
        }

        // Collect output from all children
        let mut all_stderr = String::new();
        let last = child_processes.len() - 1;
        let mut final_stdout = String::new();
        let mut final_exit_code = 0;

        for (i, child) in child_processes.into_iter().enumerate() {
            let output = child
                .wait_with_output()
                .map_err(|e| format!("failed to read output: {}", e))?;
            all_stderr.push_str(&String::from_utf8_lossy(&output.stderr));

            if i == last {
                final_stdout = String::from_utf8_lossy(&output.stdout).to_string();
                final_exit_code = exit_code(output.status);

                // Handle redirects on last command
                let redirects = &cmd_infos[last];
                if !redirects.is_empty() {
                    final_stdout = self.apply_redirects(&final_stdout, redirects)?;
                }
            }
        }

        if bang {
            final_exit_code = if final_exit_code == 0 { 1 } else { 0 };
        }

        Ok((final_stdout, all_stderr, final_exit_code))
    }

    fn execute_command(
        &self,
        command: &BrushCommand,
        local_vars: &mut HashMap<String, String>,
        _stdin_data: Option<String>,
    ) -> Result<(String, String, i32), String> {
        match command {
            BrushCommand::Simple(simple) => {
                self.execute_simple_command(simple, local_vars, _stdin_data)
            }
            BrushCommand::Compound(compound, redirects) => {
                let (mut stdout, stderr, code) =
                    self.execute_compound_command(compound, local_vars)?;
                if let Some(redirect_list) = redirects {
                    let io_redirects = self.collect_redirects_from_list(redirect_list, local_vars);
                    if !io_redirects.is_empty() {
                        stdout = self.apply_redirects(&stdout, &io_redirects)?;
                    }
                }
                Ok((stdout, stderr, code))
            }
            BrushCommand::Function(_) => Err("function definitions are not allowed".to_string()),
            BrushCommand::ExtendedTest(_) => {
                // [[ ... ]] — we don't execute these, but we could in the future.
                // For now, return success (the validator already checked the contents).
                Err("extended test expressions [[ ]] are not supported for execution".to_string())
            }
        }
    }

    fn execute_simple_command(
        &self,
        cmd: &SimpleCommand,
        local_vars: &mut HashMap<String, String>,
        stdin_data: Option<String>,
    ) -> Result<(String, String, i32), String> {
        let (name, args, redirects, _stderr_behavior) =
            self.extract_simple_command(cmd, local_vars)?;

        let mut process = Command::new(&name);
        process.args(&args);
        process.current_dir(&self.working_dir);
        self.configure_env(&mut process);

        if stdin_data.is_some() {
            process.stdin(Stdio::piped());
        }

        process.stdout(Stdio::piped());
        process.stderr(Stdio::piped());

        let mut child = process
            .spawn()
            .map_err(|e| format!("failed to spawn '{}': {}", name, e))?;

        if let Some(data) = stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(data.as_bytes());
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to read output: {}", e))?;

        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = exit_code(output.status);

        if !redirects.is_empty() {
            stdout = self.apply_redirects(&stdout, &redirects)?;
        }

        Ok((stdout, stderr, exit_code))
    }

    /// Extract command name, expanded args, redirects, and stderr behavior from a SimpleCommand.
    fn extract_simple_command(
        &self,
        cmd: &SimpleCommand,
        local_vars: &HashMap<String, String>,
    ) -> Result<(String, Vec<String>, Vec<RedirectInfo>, StderrBehavior), String> {
        let name = match &cmd.word_or_name {
            Some(w) => self.expand_word_to_string(w, local_vars)?,
            None => return Err("empty command".to_string()),
        };

        let mut args = Vec::new();
        let mut redirects = Vec::new();
        let mut stderr_behavior = StderrBehavior::Capture;

        // Process prefix and suffix items
        let prefix_items = cmd.prefix.iter().flat_map(|p| &p.0);
        let suffix_items = cmd.suffix.iter().flat_map(|s| &s.0);
        for item in prefix_items.chain(suffix_items) {
            match item {
                CommandPrefixOrSuffixItem::Word(w) => {
                    let expanded = self.expand_word(w, local_vars)?;
                    for arg in &expanded {
                        self.check_expanded_arg_path(arg)?;
                    }
                    args.extend(expanded);
                }
                CommandPrefixOrSuffixItem::IoRedirect(r) => {
                    // Detect stderr behavior from the redirect
                    let behavior = Self::detect_stderr_behavior(r);
                    if behavior != StderrBehavior::Capture {
                        stderr_behavior = behavior;
                    }
                    redirects.extend(self.extract_redirect(r, local_vars)?);
                }
                _ => {}
            }
        }

        Ok((name, args, redirects, stderr_behavior))
    }

    /// Detect stderr behavior from an IoRedirect AST node.
    fn detect_stderr_behavior(redirect: &IoRedirect) -> StderrBehavior {
        match redirect {
            IoRedirect::File(fd, kind, target) => {
                // Only look at fd 2 redirects
                if *fd != Some(2) {
                    return StderrBehavior::Capture;
                }
                match kind {
                    IoFileRedirectKind::DuplicateOutput => {
                        // 2>&1
                        match target {
                            IoFileRedirectTarget::Fd(1) => StderrBehavior::MergeToStdout,
                            IoFileRedirectTarget::Duplicate(w) if w.value == "1" => {
                                StderrBehavior::MergeToStdout
                            }
                            _ => StderrBehavior::Capture,
                        }
                    }
                    IoFileRedirectKind::Write
                    | IoFileRedirectKind::Append
                    | IoFileRedirectKind::Clobber => {
                        // 2>/dev/null
                        if let IoFileRedirectTarget::Filename(w) = target {
                            if w.value == "/dev/null" {
                                return StderrBehavior::DevNull;
                            }
                        }
                        StderrBehavior::Capture
                    }
                    _ => StderrBehavior::Capture,
                }
            }
            IoRedirect::OutputAndError(target, _) => {
                // &>/dev/null
                if target.value == "/dev/null" {
                    StderrBehavior::DevNull
                } else {
                    StderrBehavior::Capture
                }
            }
            _ => StderrBehavior::Capture,
        }
    }

    fn execute_compound_command(
        &self,
        compound: &CompoundCommand,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        match compound {
            CompoundCommand::BraceGroup(bg) => self.execute_compound_list(&bg.list, local_vars),
            CompoundCommand::Subshell(sub) => {
                // Execute in a "subshell" (we don't fork, but local_vars don't leak out)
                let mut sub_vars = local_vars.clone();
                self.execute_compound_list(&sub.list, &mut sub_vars)
            }
            CompoundCommand::ForClause(fc) => self.execute_for_clause(fc, local_vars),
            CompoundCommand::WhileClause(wc) => {
                self.execute_while_clause(&wc.0, &wc.1.list, true, local_vars)
            }
            CompoundCommand::UntilClause(uc) => {
                self.execute_while_clause(&uc.0, &uc.1.list, false, local_vars)
            }
            CompoundCommand::IfClause(ic) => self.execute_if_clause(ic, local_vars),
            CompoundCommand::CaseClause(cc) => self.execute_case_clause(cc, local_vars),
            CompoundCommand::Arithmetic(_) => {
                // (( expr )) — not supported for execution yet
                Ok((String::new(), String::new(), 0))
            }
            CompoundCommand::ArithmeticForClause(_) => {
                Err("arithmetic for loops (( )) are not supported".to_string())
            }
        }
    }

    fn execute_for_clause(
        &self,
        fc: &ForClauseCommand,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let mut all_stdout = String::new();
        let mut all_stderr = String::new();
        let mut last_code = 0;

        // Expand the values to iterate over
        let values: Vec<String> = if let Some(word_values) = &fc.values {
            let mut vals = Vec::new();
            for w in word_values {
                vals.extend(self.expand_word(w, local_vars)?);
            }
            vals
        } else {
            // Default: iterate over positional parameters (not supported in rsh)
            Vec::new()
        };

        if values.len() > MAX_LOOP_ITERATIONS {
            return Err(format!(
                "for loop has {} iterations, exceeding maximum ({})",
                values.len(),
                MAX_LOOP_ITERATIONS
            ));
        }

        for value in values {
            local_vars.insert(fc.variable_name.clone(), value);
            let (stdout, stderr, code) = self.execute_compound_list(&fc.body.list, local_vars)?;
            all_stdout.push_str(&stdout);
            all_stderr.push_str(&stderr);
            last_code = code;
        }

        Ok((all_stdout, all_stderr, last_code))
    }

    fn execute_while_clause(
        &self,
        condition: &CompoundList,
        body: &CompoundList,
        is_while: bool,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let mut all_stdout = String::new();
        let mut all_stderr = String::new();
        let mut last_code = 0;
        let mut iterations = 0;

        loop {
            if iterations >= MAX_LOOP_ITERATIONS {
                return Err(format!(
                    "loop exceeded maximum iterations ({})",
                    MAX_LOOP_ITERATIONS
                ));
            }
            iterations += 1;

            let (cond_stdout, cond_stderr, cond_code) =
                self.execute_compound_list(condition, local_vars)?;
            all_stdout.push_str(&cond_stdout);
            all_stderr.push_str(&cond_stderr);

            let should_continue = if is_while {
                cond_code == 0
            } else {
                cond_code != 0
            };

            if !should_continue {
                break;
            }

            let (body_stdout, body_stderr, body_code) =
                self.execute_compound_list(body, local_vars)?;
            all_stdout.push_str(&body_stdout);
            all_stderr.push_str(&body_stderr);
            last_code = body_code;
        }

        Ok((all_stdout, all_stderr, last_code))
    }

    fn execute_if_clause(
        &self,
        ic: &IfClauseCommand,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let mut all_stdout = String::new();
        let mut all_stderr = String::new();

        // Evaluate condition
        let (cond_stdout, cond_stderr, cond_code) =
            self.execute_compound_list(&ic.condition, local_vars)?;
        all_stdout.push_str(&cond_stdout);
        all_stderr.push_str(&cond_stderr);

        if cond_code == 0 {
            // Condition true — execute then branch
            let (then_stdout, then_stderr, then_code) =
                self.execute_compound_list(&ic.then, local_vars)?;
            all_stdout.push_str(&then_stdout);
            all_stderr.push_str(&then_stderr);
            return Ok((all_stdout, all_stderr, then_code));
        }

        // Try elif/else clauses
        if let Some(elses) = &ic.elses {
            for else_clause in elses {
                if let Some(elif_condition) = &else_clause.condition {
                    let (elif_stdout, elif_stderr, elif_code) =
                        self.execute_compound_list(elif_condition, local_vars)?;
                    all_stdout.push_str(&elif_stdout);
                    all_stderr.push_str(&elif_stderr);

                    if elif_code == 0 {
                        let (body_stdout, body_stderr, body_code) =
                            self.execute_compound_list(&else_clause.body, local_vars)?;
                        all_stdout.push_str(&body_stdout);
                        all_stderr.push_str(&body_stderr);
                        return Ok((all_stdout, all_stderr, body_code));
                    }
                } else {
                    // else (no condition)
                    let (body_stdout, body_stderr, body_code) =
                        self.execute_compound_list(&else_clause.body, local_vars)?;
                    all_stdout.push_str(&body_stdout);
                    all_stderr.push_str(&body_stderr);
                    return Ok((all_stdout, all_stderr, body_code));
                }
            }
        }

        // No branch matched
        Ok((all_stdout, all_stderr, 0))
    }

    fn execute_case_clause(
        &self,
        cc: &CaseClauseCommand,
        local_vars: &mut HashMap<String, String>,
    ) -> Result<(String, String, i32), String> {
        let value = self.expand_word_to_string(&cc.value, local_vars)?;
        let mut all_stdout = String::new();
        let mut all_stderr = String::new();

        for case_item in &cc.cases {
            let mut matched = false;
            for pattern in &case_item.patterns {
                let pat = self.expand_word_to_string(pattern, local_vars)?;
                if shell_pattern_matches(&pat, &value) {
                    matched = true;
                    break;
                }
            }
            if matched {
                if let Some(cmd_list) = &case_item.cmd {
                    let (stdout, stderr, code) =
                        self.execute_compound_list(cmd_list, local_vars)?;
                    all_stdout.push_str(&stdout);
                    all_stderr.push_str(&stderr);
                    return Ok((all_stdout, all_stderr, code));
                }
                return Ok((all_stdout, all_stderr, 0));
            }
        }

        Ok((all_stdout, all_stderr, 0))
    }

    // --- Word expansion ---

    /// Expand a word to a single string (no word splitting, no glob).
    fn expand_word_to_string(
        &self,
        word: &Word,
        local_vars: &HashMap<String, String>,
    ) -> Result<String, String> {
        let opts = ParserOptions::default();
        let pieces =
            word::parse(&word.value, &opts).map_err(|e| format!("word parse error: {}", e))?;
        self.expand_pieces(&pieces, local_vars)
    }

    /// Expand a word, potentially producing multiple strings (glob expansion + word splitting).
    fn expand_word(
        &self,
        word: &Word,
        local_vars: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        // Parse word pieces once and reuse for all checks + expansion
        let opts = ParserOptions::default();
        let pieces =
            word::parse(&word.value, &opts).map_err(|e| format!("word parse error: {}", e))?;

        let needs_split = pieces_need_splitting(&pieces);
        let expanded = self.expand_pieces(&pieces, local_vars)?;

        if needs_split {
            // Word-split by whitespace (IFS), then glob-expand each part
            let mut results = Vec::new();
            for part in expanded.split_whitespace() {
                if rsh_glob::is_glob(part) {
                    results.extend(rsh_glob::expand_glob(part, &self.working_dir)?);
                } else {
                    results.push(part.to_string());
                }
            }
            if results.is_empty() {
                return Ok(Vec::new());
            }
            return Ok(results);
        }

        // Try glob expansion — only on words that have unquoted glob chars
        if pieces_have_unquoted_glob(&pieces) {
            return rsh_glob::expand_glob(&expanded, &self.working_dir);
        }

        Ok(vec![expanded])
    }

    /// Expand a parsed word piece list into a single string.
    fn expand_pieces(
        &self,
        pieces: &[word::WordPieceWithSource],
        local_vars: &HashMap<String, String>,
    ) -> Result<String, String> {
        let mut result = String::new();
        for p in pieces {
            result.push_str(&self.expand_piece(&p.piece, local_vars)?);
        }
        Ok(result)
    }

    fn expand_piece(
        &self,
        piece: &WordPiece,
        local_vars: &HashMap<String, String>,
    ) -> Result<String, String> {
        match piece {
            WordPiece::Text(s) => Ok(s.clone()),
            WordPiece::SingleQuotedText(s) => Ok(s.clone()),
            WordPiece::AnsiCQuotedText(s) => Ok(s.clone()),
            WordPiece::EscapeSequence(s) => {
                // Interpret common escape sequences
                if s.len() == 2 && s.starts_with('\\') {
                    let ch = s.chars().nth(1).unwrap();
                    match ch {
                        'n' => Ok("\n".to_string()),
                        't' => Ok("\t".to_string()),
                        'r' => Ok("\r".to_string()),
                        '\\' => Ok("\\".to_string()),
                        _ => Ok(ch.to_string()),
                    }
                } else {
                    Ok(s.clone())
                }
            }
            WordPiece::TildePrefix(_) => {
                // Tilde expansion is blocked by the validator (~ expands to an absolute path).
                // Reject here too as defense-in-depth.
                Err("tilde expansion (~) is not allowed".to_string())
            }
            WordPiece::ParameterExpansion(expr) => self.expand_parameter(expr, local_vars),
            WordPiece::CommandSubstitution(cmd_str) => {
                self.execute_command_substitution(cmd_str, local_vars)
            }
            WordPiece::BackquotedCommandSubstitution(cmd_str) => {
                self.execute_command_substitution(cmd_str, local_vars)
            }
            WordPiece::DoubleQuotedSequence(pieces) => {
                let mut result = String::new();
                for p in pieces {
                    result.push_str(&self.expand_piece(&p.piece, local_vars)?);
                }
                Ok(result)
            }
            WordPiece::GettextDoubleQuotedSequence(pieces) => {
                let mut result = String::new();
                for p in pieces {
                    result.push_str(&self.expand_piece(&p.piece, local_vars)?);
                }
                Ok(result)
            }
            WordPiece::ArithmeticExpression(_) => {
                // Arithmetic expansion — not fully supported
                Ok(String::new())
            }
        }
    }

    fn expand_parameter(
        &self,
        expr: &ParameterExpr,
        local_vars: &HashMap<String, String>,
    ) -> Result<String, String> {
        match expr {
            ParameterExpr::Parameter { parameter, .. } => {
                self.resolve_parameter(parameter, local_vars)
            }
            ParameterExpr::UseDefaultValues {
                parameter,
                default_value,
                test_type,
                ..
            } => {
                let val = self.resolve_parameter(parameter, local_vars)?;
                let is_empty = match test_type {
                    word::ParameterTestType::UnsetOrNull => val.is_empty(),
                    word::ParameterTestType::Unset => false, // We always have a value (possibly empty)
                };
                if is_empty {
                    if let Some(default) = default_value {
                        let opts = ParserOptions::default();
                        let pieces = word::parse(default, &opts)
                            .map_err(|e| format!("word parse error: {}", e))?;
                        self.expand_pieces(&pieces, local_vars)
                    } else {
                        Ok(String::new())
                    }
                } else {
                    Ok(val)
                }
            }
            _ => {
                // For other complex parameter operations, try basic resolution
                Ok(String::new())
            }
        }
    }

    fn resolve_parameter(
        &self,
        param: &Parameter,
        local_vars: &HashMap<String, String>,
    ) -> Result<String, String> {
        match param {
            Parameter::Named(name) => {
                // Only resolve from local vars (for-loop variables).
                // Never fall back to environment — the validator only approves
                // for-loop variables, and those are always in local_vars.
                Ok(local_vars.get(name.as_str()).cloned().unwrap_or_default())
            }
            Parameter::Special(sp) => match sp {
                word::SpecialParameter::LastExitStatus => {
                    Ok(local_vars.get("?").cloned().unwrap_or_else(|| "0".to_string()))
                }
                word::SpecialParameter::ProcessId => Ok(std::process::id().to_string()),
                _ => Ok(String::new()),
            },
            Parameter::Positional(_) => Ok(String::new()),
            Parameter::NamedWithIndex { name, .. }
            | Parameter::NamedWithAllIndices { name, .. } => {
                Ok(local_vars.get(name.as_str()).cloned().unwrap_or_default())
            }
        }
    }

    /// Execute a command substitution $(...) or `...`
    fn execute_command_substitution(
        &self,
        cmd_str: &str,
        local_vars: &HashMap<String, String>,
    ) -> Result<String, String> {
        // Parse the inner command
        let reader = std::io::Cursor::new(cmd_str);
        let mut parser = brush_parser::Parser::builder().reader(reader).build();
        let inner_program = parser
            .parse_program()
            .map_err(|e| format!("parse error in command substitution: {}", e))?;

        // Execute it
        let mut sub_vars = local_vars.clone();
        let (stdout, _stderr, _code) = self.execute_program(&inner_program, &mut sub_vars)?;

        // Trim trailing newline (shell behavior)
        Ok(stdout.trim_end_matches('\n').to_string())
    }

    // --- Environment ---

    fn configure_env(&self, process: &mut Command) {
        if !self.inherit_env {
            process.env_clear();
            for var in allowlist::FORWARDED_VARS {
                if let Ok(val) = std::env::var(var) {
                    process.env(var, val);
                }
            }
        }
    }

    // --- Path checking ---

    /// Check expanded argument values for absolute paths and path traversal.
    fn check_expanded_arg_path(&self, arg: &str) -> Result<(), String> {
        validator::check_arg_path_safety(arg)
    }

    // --- Redirects ---

    fn extract_redirect(
        &self,
        redirect: &IoRedirect,
        local_vars: &HashMap<String, String>,
    ) -> Result<Vec<RedirectInfo>, String> {
        match redirect {
            IoRedirect::File(fd, kind, target) => {
                // Only handle stdout redirects (fd 1 or unspecified).
                // fd 2 (stderr) redirects like 2>/dev/null and fd duplication
                // like 2>&1 are validated but not executed post-hoc — rsh
                // captures stdout/stderr separately via Stdio::piped().
                if let Some(fd_num) = fd {
                    if *fd_num != 1 {
                        return Ok(Vec::new());
                    }
                }
                let redir_kind = match kind {
                    IoFileRedirectKind::Write | IoFileRedirectKind::Clobber => {
                        RedirectKindSimple::Overwrite
                    }
                    IoFileRedirectKind::Append => RedirectKindSimple::Append,
                    _ => return Ok(Vec::new()), // Other redirects handled by validator
                };
                let target_str = match target {
                    IoFileRedirectTarget::Filename(w) => {
                        self.expand_word_to_string(w, local_vars)?
                    }
                    _ => return Ok(Vec::new()),
                };
                Ok(vec![RedirectInfo {
                    kind: redir_kind,
                    target: target_str,
                }])
            }
            IoRedirect::OutputAndError(target, append) => {
                // &> file or &>> file — redirect both stdout and stderr to file
                let target_str = self.expand_word_to_string(target, local_vars)?;
                let kind = if *append {
                    RedirectKindSimple::Append
                } else {
                    RedirectKindSimple::Overwrite
                };
                Ok(vec![RedirectInfo {
                    kind,
                    target: target_str,
                }])
            }
            _ => Ok(Vec::new()),
        }
    }

    fn collect_redirects_from_list(
        &self,
        list: &RedirectList,
        local_vars: &HashMap<String, String>,
    ) -> Vec<RedirectInfo> {
        let mut result = Vec::new();
        for r in &list.0 {
            if let Ok(infos) = self.extract_redirect(r, local_vars) {
                result.extend(infos);
            }
        }
        result
    }

    fn apply_redirects(&self, stdout: &str, redirects: &[RedirectInfo]) -> Result<String, String> {
        for redirect in redirects {
            // /dev/null — just discard the output
            if redirect.target == "/dev/null" {
                return Ok(String::new());
            }

            if redirect.target.starts_with('/') {
                return Err(format!(
                    "absolute redirect path '{}' not allowed",
                    redirect.target
                ));
            }
            let path = self.working_dir.join(&redirect.target);

            // Path traversal guard
            let canon_working = self
                .working_dir
                .canonicalize()
                .map_err(|e| format!("cannot canonicalize working dir: {}", e))?;
            let parent = path.parent().unwrap_or(&path);
            let canon_parent = if parent.exists() {
                parent
                    .canonicalize()
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
                RedirectKindSimple::Overwrite => {
                    let mut f = File::create(&path).map_err(|e| {
                        format!("cannot open '{}' for writing: {}", redirect.target, e)
                    })?;
                    f.write_all(stdout.as_bytes())
                        .map_err(|e| format!("write error: {}", e))?;
                }
                RedirectKindSimple::Append => {
                    let mut f = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                        .map_err(|e| {
                            format!("cannot open '{}' for appending: {}", redirect.target, e)
                        })?;
                    f.write_all(stdout.as_bytes())
                        .map_err(|e| format!("write error: {}", e))?;
                }
            }
        }
        Ok(String::new())
    }
}

// Use a type alias to avoid confusion with brush_parser's Command
use brush_parser::ast::Command as BrushCommand;

/// Simple redirect info extracted from the AST.
#[derive(Debug, Clone)]
struct RedirectInfo {
    kind: RedirectKindSimple,
    target: String,
}

#[derive(Debug, Clone)]
enum RedirectKindSimple {
    Overwrite,
    Append,
}

/// What to do with stderr for a command.
#[derive(Debug, Clone, PartialEq)]
enum StderrBehavior {
    /// Default: capture stderr via piped()
    Capture,
    /// 2>/dev/null or &>/dev/null: discard stderr
    DevNull,
    /// 2>&1: merge stderr into stdout
    MergeToStdout,
}

/// Check if parsed word pieces contain unquoted glob characters.
fn pieces_have_unquoted_glob(pieces: &[word::WordPieceWithSource]) -> bool {
    pieces
        .iter()
        .any(|p| matches!(&p.piece, WordPiece::Text(s) if rsh_glob::is_glob(s)))
}

/// Check if parsed word pieces contain unquoted command substitution (needs word splitting).
fn pieces_need_splitting(pieces: &[word::WordPieceWithSource]) -> bool {
    pieces.iter().any(|p| {
        matches!(
            &p.piece,
            WordPiece::CommandSubstitution(_) | WordPiece::BackquotedCommandSubstitution(_)
        )
    })
}

/// Simple shell glob pattern matching for case statements.
fn shell_pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Use glob-style matching
    let glob_pattern = glob::Pattern::new(pattern);
    match glob_pattern {
        Ok(p) => p.matches(value),
        Err(_) => pattern == value,
    }
}
