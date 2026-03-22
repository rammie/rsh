/// Recursive AST security walker for brush-parser ASTs.
///
/// Walks every node in a `brush_parser::ast::Program` and enforces:
/// - Command allowlist (including sub-commands in find -exec, xargs, etc.)
/// - Blocked flags (-delete, -ok, -okdir on find; -p/--interactive on xargs)
/// - Variable reference approval
/// - Redirect gating (--allow-redirects)
/// - Path traversal / absolute path checks
/// - Rejection of function definitions, background (&), and process substitution

use std::collections::HashSet;

use brush_parser::ast::*;
use brush_parser::word::{self, Parameter, ParameterExpr, WordPiece};
use brush_parser::ParserOptions;

use crate::allowlist::{self, Allowlist};

/// Flags that are always forbidden on specific commands (destructive or interactive).
const UNCONDITIONALLY_BLOCKED: &[(&str, &[&str])] = &[
    ("find", &["-delete", "-ok", "-okdir"]),
];

/// Flags blocked by prefix match (e.g., sed -i, sed -i.bak, sed -ibak all blocked).
const PREFIX_BLOCKED: &[(&str, &[&str])] = &[
    ("sed", &["-i", "--in-place"]),
    ("sort", &["-o", "--output"]),
];

/// Flags that trigger sub-command execution on specific commands.
const EXEC_FLAGS: &[(&str, &[&str])] = &[
    ("find", &["-exec", "-execdir"]),
    ("fd", &["-x", "--exec", "-X", "--exec-batch"]),
];

/// xargs flags that consume the next token as their value.
const XARGS_FLAGS_WITH_ARG: &[&str] = &[
    "-I", "-L", "-n", "-P", "-s", "-d", "-E", "-J", "-R",
];

/// xargs flags that are always blocked (interactive / dangerous).
const XARGS_BLOCKED_FLAGS: &[&str] = &["-p", "--interactive"];


/// Configuration passed into the validator.
pub struct ValidatorConfig {
    pub allow_redirects: bool,
    pub allow_absolute: bool,
}

/// Validate a brush-parser Program against the security policy.
/// Returns the list of command names on success, or an error message.
pub fn validate(
    program: &Program,
    allowlist: &Allowlist,
    config: &ValidatorConfig,
) -> Result<Vec<String>, String> {
    let approved_vars: HashSet<String> = allowlist::APPROVED_VARS.iter().map(|s| s.to_string()).collect();
    let mut ctx = ValidatorContext {
        allowlist,
        config,
        approved_vars,
        command_names: Vec::new(),
    };
    ctx.validate_program(program)?;
    Ok(ctx.command_names)
}

struct ValidatorContext<'a> {
    allowlist: &'a Allowlist,
    config: &'a ValidatorConfig,
    approved_vars: HashSet<String>,
    command_names: Vec<String>,
}

impl<'a> ValidatorContext<'a> {
    fn validate_program(&mut self, program: &Program) -> Result<(), String> {
        for complete_command in &program.complete_commands {
            self.validate_compound_list(complete_command)?;
        }
        Ok(())
    }

    fn validate_compound_list(&mut self, list: &CompoundList) -> Result<(), String> {
        for item in &list.0 {
            // Reject background execution (&)
            if matches!(item.1, SeparatorOperator::Async) {
                return Err("background execution (&) is not allowed".to_string());
            }
            self.validate_and_or_list(&item.0)?;
        }
        Ok(())
    }

    fn validate_and_or_list(&mut self, and_or: &AndOrList) -> Result<(), String> {
        self.validate_pipeline(&and_or.first)?;
        for additional in &and_or.additional {
            match additional {
                AndOr::And(pipeline) | AndOr::Or(pipeline) => {
                    self.validate_pipeline(pipeline)?;
                }
            }
        }
        Ok(())
    }

    fn validate_pipeline(&mut self, pipeline: &Pipeline) -> Result<(), String> {
        let num_commands = pipeline.seq.len();
        for (idx, command) in pipeline.seq.iter().enumerate() {
            self.validate_command(command, idx, num_commands)?;
        }
        Ok(())
    }

    fn validate_command(
        &mut self,
        command: &Command,
        pipeline_idx: usize,
        pipeline_len: usize,
    ) -> Result<(), String> {
        match command {
            Command::Simple(simple) => {
                self.validate_simple_command(simple, pipeline_idx, pipeline_len)
            }
            Command::Compound(compound, redirects) => {
                // Validate redirects if present
                if let Some(redirect_list) = redirects {
                    self.validate_redirect_list(redirect_list, pipeline_idx, pipeline_len, "compound command")?;
                }
                self.validate_compound_command(compound)
            }
            Command::Function(_) => {
                Err("function definitions are not allowed".to_string())
            }
            Command::ExtendedTest(test) => {
                // [[ ... ]] — validate any words/variable references inside
                self.validate_extended_test(&test.expr)
            }
        }
    }

    fn validate_simple_command(
        &mut self,
        cmd: &SimpleCommand,
        pipeline_idx: usize,
        pipeline_len: usize,
    ) -> Result<(), String> {
        // Extract command name
        let cmd_name = match &cmd.word_or_name {
            Some(w) => w.value.clone(),
            None => {
                // Assignment-only command (e.g., `VAR=value`). We reject these.
                if let Some(prefix) = &cmd.prefix {
                    for item in &prefix.0 {
                        match item {
                            CommandPrefixOrSuffixItem::AssignmentWord(_, _) => {
                                return Err("variable assignments are not allowed".to_string());
                            }
                            CommandPrefixOrSuffixItem::IoRedirect(_) => {
                                // Redirect-only command with no name — reject
                            }
                            CommandPrefixOrSuffixItem::ProcessSubstitution(_, _) => {
                                return Err("process substitution is not allowed".to_string());
                            }
                            _ => {}
                        }
                    }
                }
                return Err("empty command".to_string());
            }
        };

        // Check allowlist
        if !self.allowlist.is_allowed(&cmd_name) {
            return Err(format!(
                "command '{}' not in allowlist (allowed: {})",
                cmd_name,
                self.allowlist.allowed_commands().join(", ")
            ));
        }
        self.command_names.push(cmd_name.clone());

        // Collect all argument words and redirects from prefix + suffix
        let mut arg_words: Vec<&Word> = Vec::new();
        let mut redirects: Vec<&IoRedirect> = Vec::new();

        let prefix_items = cmd.prefix.iter().flat_map(|p| &p.0);
        let suffix_items = cmd.suffix.iter().flat_map(|s| &s.0);
        for item in prefix_items.chain(suffix_items) {
            match item {
                CommandPrefixOrSuffixItem::Word(w) => arg_words.push(w),
                CommandPrefixOrSuffixItem::IoRedirect(r) => redirects.push(r),
                CommandPrefixOrSuffixItem::AssignmentWord(_, _) => {
                    return Err("variable assignments are not allowed".to_string());
                }
                CommandPrefixOrSuffixItem::ProcessSubstitution(_, _) => {
                    return Err("process substitution is not allowed".to_string());
                }
            }
        }

        // Extract plain string values for flag-based validation
        let string_args: Vec<&str> = arg_words.iter().map(|w| w.value.as_str()).collect();

        // Check blocked flags (exact match and prefix match)
        self.check_blocked_flags(&cmd_name, &string_args, None)?;

        // Validate sub-command execution flags (-exec, --exec, etc.)
        self.validate_exec_flags(&cmd_name, &string_args)?;

        // Validate xargs
        self.validate_xargs(&cmd_name, &string_args)?;

        // Check for sed write commands (w, W) inside sed expressions
        self.check_sed_write(&cmd_name, &string_args)?;

        // Check argument paths for absolute paths and path traversal
        for arg in &string_args {
            self.check_arg_path(arg)?;
        }

        // Validate redirects
        if !redirects.is_empty() {
            if pipeline_idx < pipeline_len - 1 {
                return Err(format!(
                    "redirects on non-final pipeline command '{}' are not supported",
                    cmd_name
                ));
            }
            for r in &redirects {
                self.validate_io_redirect(r)?;
            }
        }

        // Validate variable references and command substitutions in all words
        for w in &arg_words {
            self.validate_word(w)?;
        }

        // Also validate the command name word itself (it could contain $VAR)
        if let Some(w) = &cmd.word_or_name {
            self.validate_word(w)?;
        }

        Ok(())
    }

    fn validate_compound_command(&mut self, compound: &CompoundCommand) -> Result<(), String> {
        match compound {
            CompoundCommand::BraceGroup(bg) => {
                self.validate_compound_list(&bg.list)
            }
            CompoundCommand::Subshell(sub) => {
                self.validate_compound_list(&sub.list)
            }
            CompoundCommand::ForClause(fc) => {
                // Validate the iteration values
                if let Some(values) = &fc.values {
                    for w in values {
                        self.validate_word(w)?;
                    }
                }
                // The loop variable is safe — it's locally bound
                self.approved_vars.insert(fc.variable_name.clone());
                self.validate_compound_list(&fc.body.list)
            }
            CompoundCommand::WhileClause(wc) => {
                self.validate_compound_list(&wc.0)?;
                self.validate_compound_list(&wc.1.list)
            }
            CompoundCommand::UntilClause(uc) => {
                self.validate_compound_list(&uc.0)?;
                self.validate_compound_list(&uc.1.list)
            }
            CompoundCommand::IfClause(ic) => {
                self.validate_compound_list(&ic.condition)?;
                self.validate_compound_list(&ic.then)?;
                if let Some(elses) = &ic.elses {
                    for else_clause in elses {
                        if let Some(condition) = &else_clause.condition {
                            self.validate_compound_list(condition)?;
                        }
                        self.validate_compound_list(&else_clause.body)?;
                    }
                }
                Ok(())
            }
            CompoundCommand::CaseClause(cc) => {
                self.validate_word(&cc.value)?;
                for case_item in &cc.cases {
                    for pattern in &case_item.patterns {
                        self.validate_word(pattern)?;
                    }
                    if let Some(cmd_list) = &case_item.cmd {
                        self.validate_compound_list(cmd_list)?;
                    }
                }
                Ok(())
            }
            CompoundCommand::Arithmetic(_) => {
                // (( expr )) — arithmetic only, no command execution. Allow.
                Ok(())
            }
            CompoundCommand::ArithmeticForClause(afc) => {
                self.validate_compound_list(&afc.body.list)
            }
        }
    }

    fn validate_extended_test(&mut self, expr: &ExtendedTestExpr) -> Result<(), String> {
        match expr {
            ExtendedTestExpr::And(a, b) | ExtendedTestExpr::Or(a, b) => {
                self.validate_extended_test(a)?;
                self.validate_extended_test(b)
            }
            ExtendedTestExpr::Not(inner) | ExtendedTestExpr::Parenthesized(inner) => {
                self.validate_extended_test(inner)
            }
            ExtendedTestExpr::UnaryTest(_, w) => self.validate_word(w),
            ExtendedTestExpr::BinaryTest(_, w1, w2) => {
                self.validate_word(w1)?;
                self.validate_word(w2)
            }
        }
    }

    /// Validate a Word for variable references and command substitutions.
    fn validate_word(&self, word: &Word) -> Result<(), String> {
        let opts = ParserOptions::default();
        let pieces = word::parse(&word.value, &opts)
            .map_err(|e| format!("word parse error: {}", e))?;
        for piece_with_source in &pieces {
            self.validate_word_piece(&piece_with_source.piece)?;
        }
        Ok(())
    }

    fn validate_word_piece(&self, piece: &WordPiece) -> Result<(), String> {
        match piece {
            WordPiece::ParameterExpansion(expr) => {
                self.validate_parameter_expr(expr)
            }
            WordPiece::CommandSubstitution(cmd_str) => {
                // Recursively parse and validate the substituted command
                self.validate_command_substitution(cmd_str)
            }
            WordPiece::BackquotedCommandSubstitution(cmd_str) => {
                self.validate_command_substitution(cmd_str)
            }
            WordPiece::DoubleQuotedSequence(pieces)
            | WordPiece::GettextDoubleQuotedSequence(pieces) => {
                for p in pieces {
                    self.validate_word_piece(&p.piece)?;
                }
                Ok(())
            }
            WordPiece::Text(_)
            | WordPiece::SingleQuotedText(_)
            | WordPiece::AnsiCQuotedText(_)
            | WordPiece::TildePrefix(_)
            | WordPiece::EscapeSequence(_)
            | WordPiece::ArithmeticExpression(_) => Ok(()),
        }
    }

    fn validate_parameter_expr(&self, expr: &ParameterExpr) -> Result<(), String> {
        let param = match expr {
            ParameterExpr::Parameter { parameter, .. } => parameter,
            ParameterExpr::UseDefaultValues { parameter, .. } => parameter,
            ParameterExpr::AssignDefaultValues { parameter, .. } => parameter,
            ParameterExpr::IndicateErrorIfNullOrUnset { parameter, .. } => parameter,
            ParameterExpr::UseAlternativeValue { parameter, .. } => parameter,
            ParameterExpr::ParameterLength { parameter, .. } => parameter,
            ParameterExpr::RemoveSmallestSuffixPattern { parameter, .. } => parameter,
            ParameterExpr::RemoveLargestSuffixPattern { parameter, .. } => parameter,
            ParameterExpr::RemoveSmallestPrefixPattern { parameter, .. } => parameter,
            ParameterExpr::RemoveLargestPrefixPattern { parameter, .. } => parameter,
            ParameterExpr::Substring { parameter, .. } => parameter,
            ParameterExpr::Transform { parameter, .. } => parameter,
            ParameterExpr::UppercaseFirstChar { parameter, .. } => parameter,
            ParameterExpr::UppercasePattern { parameter, .. } => parameter,
            ParameterExpr::LowercaseFirstChar { parameter, .. } => parameter,
            ParameterExpr::LowercasePattern { parameter, .. } => parameter,
            ParameterExpr::ReplaceSubstring { parameter, .. } => parameter,
            ParameterExpr::VariableNames { .. } => return Ok(()),
            ParameterExpr::MemberKeys { .. } => return Ok(()),
        };

        match param {
            Parameter::Named(name) => {
                if !self.approved_vars.contains(name.as_str()) {
                    return Err(format!(
                        "variable '{}' not in approved list (approved: {})",
                        name,
                        allowlist::APPROVED_VARS.join(", ")
                    ));
                }
            }
            Parameter::NamedWithIndex { name, .. }
            | Parameter::NamedWithAllIndices { name, .. } => {
                if !self.approved_vars.contains(name.as_str()) {
                    return Err(format!(
                        "variable '{}' not in approved list (approved: {})",
                        name,
                        allowlist::APPROVED_VARS.join(", ")
                    ));
                }
            }
            // Special parameters ($?, $#, $@, $*, $$, etc.) and positional ($1, $2)
            // are safe — they don't leak env vars.
            Parameter::Special(_) | Parameter::Positional(_) => {}
        }
        Ok(())
    }

    fn validate_command_substitution(&self, cmd_str: &str) -> Result<(), String> {
        // Parse the inner command
        let reader = std::io::Cursor::new(cmd_str);
        let mut parser = brush_parser::Parser::builder().reader(reader).build();
        let inner_program = parser.parse_program()
            .map_err(|e| format!("parse error in command substitution: {}", e))?;

        // Create a new context to validate the inner program (shares allowlist/config)
        let mut inner_ctx = ValidatorContext {
            allowlist: self.allowlist,
            config: self.config,
            approved_vars: self.approved_vars.clone(),
            command_names: Vec::new(),
        };
        inner_ctx.validate_program(&inner_program)?;
        // We don't add inner command names to the outer list — they're nested
        Ok(())
    }

    fn validate_io_redirect(&self, redirect: &IoRedirect) -> Result<(), String> {
        match redirect {
            IoRedirect::File(_, kind, target) => {
                match kind {
                    IoFileRedirectKind::DuplicateInput
                    | IoFileRedirectKind::DuplicateOutput => {
                        // fd duplication (2>&1, 1>&2, etc.) — always allowed
                        match target {
                            IoFileRedirectTarget::Fd(_) | IoFileRedirectTarget::Duplicate(_) => {
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                    IoFileRedirectKind::Write
                    | IoFileRedirectKind::Append
                    | IoFileRedirectKind::Clobber => {
                        // Output redirects to /dev/null — always allowed
                        if let IoFileRedirectTarget::Filename(w) = target {
                            if w.value == "/dev/null" {
                                return Ok(());
                            }
                        }
                        // Other file writes require --allow-redirects
                        if !self.config.allow_redirects {
                            return Err(
                                "file redirects are not allowed (use --allow-redirects to enable; \
                                 > /dev/null and fd duplication like 2>&1 are always permitted)"
                                    .to_string(),
                            );
                        }
                    }
                    IoFileRedirectKind::Read
                    | IoFileRedirectKind::ReadAndWrite => {
                        return Err("input redirection is not supported".to_string());
                    }
                }
                match target {
                    IoFileRedirectTarget::Filename(w) => {
                        self.validate_word(w)?;
                    }
                    IoFileRedirectTarget::ProcessSubstitution(_, _) => {
                        return Err("process substitution is not allowed".to_string());
                    }
                    IoFileRedirectTarget::Fd(_) | IoFileRedirectTarget::Duplicate(_) => {
                        // Already handled above for DuplicateInput/DuplicateOutput
                        return Ok(());
                    }
                }
            }
            IoRedirect::HereDocument(_, _) => {
                return Err("here-documents are not supported".to_string());
            }
            IoRedirect::HereString(_, _) => {
                return Err("here-strings are not supported".to_string());
            }
            IoRedirect::OutputAndError(target, _append) => {
                // &> /dev/null and &>> /dev/null — always allowed
                if target.value == "/dev/null" {
                    return Ok(());
                }
                if !self.config.allow_redirects {
                    return Err(
                        "file redirects are not allowed (use --allow-redirects to enable; \
                         > /dev/null and fd duplication like 2>&1 are always permitted)"
                            .to_string(),
                    );
                }
                self.validate_word(target)?;
            }
        }
        Ok(())
    }

    fn validate_redirect_list(
        &self,
        redirect_list: &RedirectList,
        pipeline_idx: usize,
        pipeline_len: usize,
        context: &str,
    ) -> Result<(), String> {
        if pipeline_idx < pipeline_len - 1 {
            return Err(format!(
                "redirects on non-final pipeline command '{}' are not supported",
                context
            ));
        }
        for r in &redirect_list.0 {
            self.validate_io_redirect(r)?;
        }
        Ok(())
    }

    // --- Sub-command validation (ported from executor.rs) ---

    fn check_sub_command(&self, sub_cmd: &str, context: &str) -> Result<(), String> {
        if sub_cmd.contains('/') || sub_cmd.contains('\\') || sub_cmd.starts_with('.') {
            return Err(format!(
                "sub-command '{}' in '{}' must be a bare command name, not a path",
                sub_cmd, context
            ));
        }
        if !self.allowlist.is_allowed(sub_cmd) {
            return Err(format!(
                "sub-command '{}' in '{}' not in allowlist (allowed: {})",
                sub_cmd, context, self.allowlist.allowed_commands().join(", ")
            ));
        }
        Ok(())
    }

    /// Check args against UNCONDITIONALLY_BLOCKED and PREFIX_BLOCKED for a command.
    /// If `context` is provided, it's included in the error message (for sub-commands).
    fn check_blocked_flags(&self, cmd: &str, args: &[&str], context: Option<&str>) -> Result<(), String> {
        if let Some((_, blocked_flags)) = UNCONDITIONALLY_BLOCKED.iter().find(|(c, _)| *c == cmd) {
            for arg in args {
                if blocked_flags.contains(arg) {
                    return Err(match context {
                        Some(ctx) => format!("'{}' flag on '{}' in {} is not allowed", arg, cmd, ctx),
                        None => format!("'{}' flag on '{}' is not allowed", arg, cmd),
                    });
                }
            }
        }
        if let Some((_, blocked_prefixes)) = PREFIX_BLOCKED.iter().find(|(c, _)| *c == cmd) {
            for arg in args {
                for prefix in *blocked_prefixes {
                    if arg.starts_with(prefix) {
                        return Err(match context {
                            Some(ctx) => format!("'{}' flag on '{}' in {} is not allowed (writes files in place)", arg, cmd, ctx),
                            None => format!("'{}' flag on '{}' is not allowed (writes files in place)", arg, cmd),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Check for sed `w` and `W` (write) commands inside sed expressions.
    /// These write to files, bypassing redirect restrictions.
    fn check_sed_write(&self, cmd: &str, args: &[&str]) -> Result<(), String> {
        if cmd != "sed" {
            return Ok(());
        }

        let mut i = 0;
        let mut found_script = false;
        while i < args.len() {
            let arg = args[i];
            // Strip surrounding quotes — brush-parser preserves them in Word.value
            let stripped = strip_quotes(arg);
            if stripped == "-e" || stripped == "--expression" {
                // Next arg is a sed expression
                i += 1;
                if i < args.len() {
                    Self::check_sed_expr_for_write(strip_quotes(args[i]))?;
                    found_script = true;
                }
            } else if stripped.starts_with("-e") {
                // -eEXPR form
                Self::check_sed_expr_for_write(&stripped[2..])?;
                found_script = true;
            } else if stripped == "-f" || stripped == "--file" {
                // -f FILE — skip the file argument
                i += 1;
                found_script = true;
            } else if stripped.starts_with('-') {
                // Other flags (e.g., -n, --quiet, etc.)
            } else if !found_script {
                // First non-flag, non-option argument is the sed script
                Self::check_sed_expr_for_write(&stripped)?;
                found_script = true;
            }
            i += 1;
        }

        Ok(())
    }

    /// Check a single sed expression for `w` or `W` (write) commands.
    fn check_sed_expr_for_write(expr: &str) -> Result<(), String> {
        // Split on ';' and newlines to handle multi-command sed scripts
        for segment in expr.split(|c: char| c == ';' || c == '\n') {
            let trimmed = segment.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Strip leading address: digits, commas, ~, $, spaces,
            // and /regex/ delimiters
            let cmd_part = strip_sed_address(trimmed);
            // Check for w or W command (write to file)
            if cmd_part.starts_with('w') || cmd_part.starts_with('W') {
                let rest = &cmd_part[1..];
                if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') || rest.starts_with('/') {
                    return Err(format!(
                        "'{}' command in sed expression writes to a file and is not allowed",
                        &cmd_part[..1]
                    ));
                }
            }
            // Also check s/pattern/replacement/ with w flag: s/p/r/w file
            if cmd_part.starts_with('s') && cmd_part.len() > 1 {
                let delim = cmd_part.as_bytes()[1];
                if let Some(flags_start) = find_s_command_flags(cmd_part, delim) {
                    let flags = &cmd_part[flags_start..];
                    if flags.contains('w') || flags.contains('W') {
                        return Err(
                            "'w' flag on sed s command writes to a file and is not allowed".to_string()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate a sub-command's flags and recursively check for nested -exec/xargs.
    fn validate_sub_command_flags(&self, sub_cmd: &str, sub_args: &[&str], context: &str) -> Result<(), String> {
        self.check_blocked_flags(sub_cmd, sub_args, Some(context))?;
        self.validate_exec_flags(sub_cmd, sub_args)?;
        self.validate_xargs(sub_cmd, sub_args)?;
        self.check_sed_write(sub_cmd, sub_args)?;
        Ok(())
    }

    /// Check a regular command argument for absolute paths and path traversal.
    /// Operates on raw Word.value strings (may include quotes).
    fn check_arg_path(&self, arg: &str) -> Result<(), String> {
        let stripped = strip_quotes(arg);
        if stripped.starts_with('-') {
            return Ok(());
        }
        if stripped.starts_with('/') && !self.config.allow_absolute {
            return Err(format!(
                "absolute path '{}' in argument not allowed (use --allow-absolute)",
                stripped
            ));
        }
        if stripped.split('/').any(|seg| seg == "..") {
            return Err(format!(
                "path traversal ('..') in argument '{}' not allowed",
                stripped
            ));
        }
        Ok(())
    }

    fn check_sub_arg_path(&self, arg: &str, context: &str) -> Result<(), String> {
        if arg.split('/').any(|seg| seg == "..") {
            return Err(format!(
                "path traversal ('..') in {} sub-command argument '{}' not allowed",
                context, arg
            ));
        }
        if arg.starts_with('/') && !self.config.allow_absolute {
            return Err(format!(
                "absolute path '{}' in {} sub-command not allowed (use --allow-absolute)",
                arg, context
            ));
        }
        Ok(())
    }

    fn validate_exec_flags(&self, cmd_name: &str, args: &[&str]) -> Result<(), String> {
        let exec_flags: &[&str] = match EXEC_FLAGS.iter().find(|(c, _)| *c == cmd_name) {
            Some((_, flags)) => flags,
            None => return Ok(()),
        };

        let mut i = 0;
        while i < args.len() {
            if exec_flags.contains(&args[i]) {
                let flag = args[i];
                i += 1;

                if i >= args.len() {
                    return Err(format!(
                        "'{}' on '{}' requires a command argument",
                        flag, cmd_name
                    ));
                }

                let context = format!("{} {}", cmd_name, flag);
                let sub_cmd = args[i];
                self.check_sub_command(sub_cmd, &context)?;

                // Collect sub-command args (everything until terminator)
                let sub_args_start = i + 1;
                i += 1;
                while i < args.len() {
                    if matches!(args[i], ";" | "+" | "{}") {
                        break;
                    }
                    self.check_sub_arg_path(args[i], &context)?;
                    i += 1;
                }

                let sub_args = &args[sub_args_start..i];

                self.validate_sub_command_flags(sub_cmd, sub_args, &context)?;
            }
            i += 1;
        }

        Ok(())
    }

    fn validate_xargs(&self, cmd_name: &str, args: &[&str]) -> Result<(), String> {
        if cmd_name != "xargs" {
            return Ok(());
        }

        let mut i = 0;
        while i < args.len() {
            let a = args[i];

            if XARGS_BLOCKED_FLAGS.contains(&a) {
                return Err(format!("'{}' flag on 'xargs' is not allowed", a));
            }

            if XARGS_FLAGS_WITH_ARG.contains(&a) {
                i += 2;
                continue;
            }

            // Short flags: combined like -I{} or clustered like -0rt
            if a.starts_with('-') && a.len() > 1 && !a.starts_with("--") {
                if XARGS_FLAGS_WITH_ARG.contains(&&a[0..2]) {
                    i += 1;
                    continue;
                }
                i += 1;
                continue;
            }

            if a.starts_with("--") {
                i += 1;
                continue;
            }

            // First positional argument is the sub-command
            self.check_sub_command(a, "xargs")?;

            let sub_args = &args[i + 1..];
            for arg in sub_args {
                self.check_sub_arg_path(arg, "xargs")?;
            }

            self.validate_sub_command_flags(a, sub_args, "xargs")?;
            return Ok(());
        }

        // No sub-command found — xargs defaults to echo
        if !self.allowlist.is_allowed("echo") {
            return Err(
                "xargs with no sub-command defaults to 'echo', which is not in the allowlist".to_string()
            );
        }
        Ok(())
    }
}

/// Strip surrounding quotes from a Word.value (brush-parser preserves them).
fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2 {
        if (s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\''))
        {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Strip a leading sed address (line numbers, ranges, /regex/) to get the command character.
fn strip_sed_address(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0;

    // Parse up to two addresses separated by comma
    for _addr in 0..2 {
        if i >= bytes.len() {
            return &s[i..];
        }
        match bytes[i] {
            b'0'..=b'9' => {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            b'$' => {
                i += 1;
            }
            b'/' => {
                // /regex/ — skip to closing /
                i += 1;
                while i < bytes.len() && bytes[i] != b'/' {
                    if bytes[i] == b'\\' {
                        i += 1; // skip escaped char
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1; // skip closing /
                }
            }
            b'\\' => {
                // \cregexc — custom delimiter
                i += 1;
                if i < bytes.len() {
                    let delim = bytes[i];
                    i += 1;
                    while i < bytes.len() && bytes[i] != delim {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                }
            }
            _ => break,
        }
        // Check for comma (address range separator)
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
        } else {
            break;
        }
    }

    // Skip optional whitespace between address and command
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }

    &s[i..]
}

/// Find the flags portion of a sed s/pattern/replacement/flags command.
/// Returns the byte offset where flags begin, or None if the s command is malformed.
fn find_s_command_flags(s: &str, delim: u8) -> Option<usize> {
    let bytes = s.as_bytes();
    // s + delim + pattern + delim + replacement + delim + flags
    // Start after 's' and first delimiter
    let mut i = 2; // skip 's' and delimiter
    let mut delim_count = 0;

    while i < bytes.len() && delim_count < 2 {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped char
            continue;
        }
        if bytes[i] == delim {
            delim_count += 1;
        }
        i += 1;
    }

    if delim_count == 2 {
        Some(i)
    } else {
        None
    }
}
