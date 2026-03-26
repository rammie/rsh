/// Recursive AST security walker for brush-parser ASTs.
///
/// Walks every node in a `brush_parser::ast::Program` and enforces:
/// - Command allowlist
/// - Blocked flags (-delete, -ok, -okdir, -exec, -execdir on find; -x/--exec on fd)
/// - Variable reference approval
/// - Redirect gating (--allow-redirects)
/// - Rejection of function definitions, background (&), and process substitution
use std::collections::HashSet;

use brush_parser::ast::*;
use brush_parser::word::{self, Parameter, ParameterExpr, WordPiece};
use brush_parser::ParserOptions;

use crate::allowlist::{self, Allowlist};

/// Flags that are always forbidden on specific commands (destructive or interactive).
const UNCONDITIONALLY_BLOCKED: &[(&str, &[&str])] = &[
    (
        "find",
        &[
            "-delete", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls", "-exec",
            "-execdir",
        ],
    ),
    ("fd", &["-x", "--exec", "-X", "--exec-batch"]),
];

/// Flags blocked by prefix match (e.g., sort -o, sort -ofoo all blocked).
const PREFIX_BLOCKED: &[(&str, &[&str])] = &[("sort", &["-o", "--output"])];

/// Configuration passed into the validator.
pub struct ValidatorConfig {
    pub allow_redirects: bool,
}

/// Validate a brush-parser Program against the security policy.
/// Returns the list of command names on success, or an error message.
pub fn validate(
    program: &Program,
    allowlist: &Allowlist,
    config: &ValidatorConfig,
) -> Result<Vec<String>, String> {
    let approved_vars: HashSet<String> = HashSet::new();
    let mut ctx = ValidatorContext {
        allowlist,
        config,
        approved_vars,
        command_names: Vec::new(),
        substitution_depth: 0,
    };
    ctx.validate_program(program)?;
    Ok(ctx.command_names)
}

struct ValidatorContext<'a> {
    allowlist: &'a Allowlist,
    config: &'a ValidatorConfig,
    approved_vars: HashSet<String>,
    command_names: Vec<String>,
    substitution_depth: usize,
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
                    self.validate_redirect_list(
                        redirect_list,
                        pipeline_idx,
                        pipeline_len,
                        "compound command",
                    )?;
                }
                self.validate_compound_command(compound)
            }
            Command::Function(_) => Err("function definitions are not allowed".to_string()),
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

        check_command_allowed(&cmd_name, self.allowlist)?;
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
        self.check_blocked_flags(&cmd_name, &string_args)?;

        // Validate redirects
        if !redirects.is_empty() {
            self.validate_redirects(&redirects, pipeline_idx, pipeline_len, &cmd_name)?;
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
            CompoundCommand::BraceGroup(bg) => self.validate_compound_list(&bg.list),
            CompoundCommand::Subshell(sub) => self.validate_compound_list(&sub.list),
            CompoundCommand::ForClause(fc) => {
                // Validate the iteration values
                if let Some(values) = &fc.values {
                    for w in values {
                        self.validate_word(w)?;
                    }
                }
                // Approve the loop variable only within the body scope
                let had_var = self.approved_vars.contains(&fc.variable_name);
                self.approved_vars.insert(fc.variable_name.clone());
                let result = self.validate_compound_list(&fc.body.list);
                if !had_var {
                    self.approved_vars.remove(&fc.variable_name);
                }
                result
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
        self.validate_word_str(&word.value)
    }

    /// Validate a raw string as a word — parses it for variable references,
    /// command substitutions, etc. Used for both Word values and sub-expression
    /// strings inside parameter expansions.
    fn validate_word_str(&self, s: &str) -> Result<(), String> {
        let opts = ParserOptions::default();
        let pieces =
            word::parse(s, &opts).map_err(|e| format!("word parse error: {}", e))?;
        for piece_with_source in &pieces {
            self.validate_word_piece(&piece_with_source.piece)?;
        }
        Ok(())
    }

    fn validate_word_piece(&self, piece: &WordPiece) -> Result<(), String> {
        match piece {
            WordPiece::ParameterExpansion(expr) => self.validate_parameter_expr(expr),
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
            WordPiece::TildePrefix(_) => Err(
                "tilde expansion (~) is not allowed (~ expands to an absolute path)".to_string(),
            ),
            WordPiece::ArithmeticExpression(expr) => {
                // Arithmetic expressions can contain command substitutions
                // like $(($(malicious_command))). Validate the inner expression.
                self.validate_word_str(&expr.value)
            }
            WordPiece::Text(_)
            | WordPiece::SingleQuotedText(_)
            | WordPiece::AnsiCQuotedText(_)
            | WordPiece::EscapeSequence(_) => Ok(()),
        }
    }

    fn validate_parameter_expr(&self, expr: &ParameterExpr) -> Result<(), String> {
        // Helper: validate an optional sub-expression string inline.
        let validate_opt = |opt: &Option<String>| -> Result<(), String> {
            if let Some(s) = opt {
                self.validate_word_str(s)?;
            }
            Ok(())
        };

        let param = match expr {
            ParameterExpr::Parameter { parameter, .. }
            | ParameterExpr::ParameterLength { parameter, .. }
            | ParameterExpr::Transform { parameter, .. } => parameter,
            ParameterExpr::Substring {
                parameter,
                offset,
                length,
                ..
            } => {
                // Validate offset/length arithmetic expressions — they can contain
                // command substitutions like $(malicious_command).
                self.validate_word_str(&offset.value)?;
                if let Some(len) = length {
                    self.validate_word_str(&len.value)?;
                }
                parameter
            }
            ParameterExpr::UseDefaultValues {
                parameter,
                default_value,
                ..
            } => {
                validate_opt(default_value)?;
                parameter
            }
            ParameterExpr::AssignDefaultValues { .. } => {
                return Err(
                    "variable assignment via ${var:=default} is not allowed".to_string(),
                );
            }
            ParameterExpr::IndicateErrorIfNullOrUnset {
                parameter,
                error_message,
                ..
            } => {
                validate_opt(error_message)?;
                parameter
            }
            ParameterExpr::UseAlternativeValue {
                parameter,
                alternative_value,
                ..
            } => {
                validate_opt(alternative_value)?;
                parameter
            }
            ParameterExpr::RemoveSmallestSuffixPattern {
                parameter, pattern, ..
            }
            | ParameterExpr::RemoveLargestSuffixPattern {
                parameter, pattern, ..
            }
            | ParameterExpr::RemoveSmallestPrefixPattern {
                parameter, pattern, ..
            }
            | ParameterExpr::RemoveLargestPrefixPattern {
                parameter, pattern, ..
            }
            | ParameterExpr::UppercaseFirstChar {
                parameter, pattern, ..
            }
            | ParameterExpr::UppercasePattern {
                parameter, pattern, ..
            }
            | ParameterExpr::LowercaseFirstChar {
                parameter, pattern, ..
            }
            | ParameterExpr::LowercasePattern {
                parameter, pattern, ..
            } => {
                validate_opt(pattern)?;
                parameter
            }
            ParameterExpr::ReplaceSubstring {
                parameter,
                pattern,
                replacement,
                ..
            } => {
                self.validate_word_str(pattern)?;
                validate_opt(replacement)?;
                parameter
            }
            ParameterExpr::VariableNames { .. } => {
                return Err("variable name expansion (${!prefix@}) is not supported".to_string());
            }
            ParameterExpr::MemberKeys { .. } => {
                return Err("associative array key expansion (${!name[@]}) is not supported".to_string());
            }
        };

        // Validate the parameter name
        match param {
            Parameter::Named(name) => {
                if !self.approved_vars.contains(name.as_str()) {
                    return Err(self.var_not_approved_error(name));
                }
            }
            Parameter::NamedWithIndex { name, index } => {
                if !self.approved_vars.contains(name.as_str()) {
                    return Err(self.var_not_approved_error(name));
                }
                self.validate_word_str(index)?;
            }
            Parameter::NamedWithAllIndices { name, .. } => {
                if !self.approved_vars.contains(name.as_str()) {
                    return Err(self.var_not_approved_error(name));
                }
            }
            // Special parameters ($?, $#, $@, $*, $$, etc.) and positional ($1, $2)
            // are safe — they don't leak env vars.
            Parameter::Special(_) | Parameter::Positional(_) => {}
        }

        Ok(())
    }

    fn var_not_approved_error(&self, name: &str) -> String {
        format!("variable '{}' is not allowed in arguments", name)
    }

    fn validate_command_substitution(&self, cmd_str: &str) -> Result<(), String> {
        if self.substitution_depth >= allowlist::MAX_SUBSTITUTION_DEPTH {
            return Err(format!(
                "command substitution nested too deeply (max {})",
                allowlist::MAX_SUBSTITUTION_DEPTH
            ));
        }

        // Parse the inner command
        let reader = std::io::Cursor::new(cmd_str);
        let mut parser = brush_parser::Parser::builder().reader(reader).build();
        let inner_program = parser
            .parse_program()
            .map_err(|e| format!("parse error in command substitution: {}", e))?;

        // Create a new context to validate the inner program (shares allowlist/config)
        let mut inner_ctx = ValidatorContext {
            allowlist: self.allowlist,
            config: self.config,
            approved_vars: self.approved_vars.clone(),
            command_names: Vec::new(),
            substitution_depth: self.substitution_depth + 1,
        };
        inner_ctx.validate_program(&inner_program)?;
        // We don't add inner command names to the outer list — they're nested
        Ok(())
    }

    /// Check if a redirect is safe to use on non-final pipeline commands.
    /// Allows: fd duplication (2>&1), writes to /dev/null (2>/dev/null, &>/dev/null).
    fn is_safe_redirect(redirect: &IoRedirect) -> bool {
        match redirect {
            IoRedirect::File(_, kind, target) => match kind {
                IoFileRedirectKind::DuplicateInput | IoFileRedirectKind::DuplicateOutput => {
                    matches!(
                        target,
                        IoFileRedirectTarget::Fd(_) | IoFileRedirectTarget::Duplicate(_)
                    )
                }
                IoFileRedirectKind::Write
                | IoFileRedirectKind::Append
                | IoFileRedirectKind::Clobber => {
                    matches!(target, IoFileRedirectTarget::Filename(w) if w.value == "/dev/null")
                }
                _ => false,
            },
            IoRedirect::OutputAndError(target, _) => target.value == "/dev/null",
            _ => false,
        }
    }

    fn validate_io_redirect(&self, redirect: &IoRedirect) -> Result<(), String> {
        match redirect {
            IoRedirect::File(_, kind, target) => {
                match kind {
                    IoFileRedirectKind::DuplicateInput | IoFileRedirectKind::DuplicateOutput => {
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
                    IoFileRedirectKind::Read | IoFileRedirectKind::ReadAndWrite => {
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
        let refs: Vec<&IoRedirect> = redirect_list.0.iter().collect();
        self.validate_redirects(&refs, pipeline_idx, pipeline_len, context)
    }

    fn validate_redirects(
        &self,
        redirects: &[&IoRedirect],
        pipeline_idx: usize,
        pipeline_len: usize,
        context: &str,
    ) -> Result<(), String> {
        let is_mid_pipeline = pipeline_idx < pipeline_len - 1;
        for r in redirects {
            if is_mid_pipeline && !Self::is_safe_redirect(r) {
                return Err(format!(
                    "redirects on non-final pipeline command '{}' are not supported \
                     (2>/dev/null and 2>&1 are allowed)",
                    context
                ));
            }
            self.validate_io_redirect(r)?;
        }
        Ok(())
    }

    /// Check args against UNCONDITIONALLY_BLOCKED and PREFIX_BLOCKED for a command.
    fn check_blocked_flags(&self, cmd: &str, args: &[&str]) -> Result<(), String> {
        check_blocked_flags(cmd, args)
    }
}

/// Check an argument string for absolute paths and path traversal.
/// For flags (args starting with `-`), checks:
///   - The value portion after `=` (e.g., `--file=/etc/passwd`)
///   - The value concatenated after a short flag letter (e.g., `-f/etc/passwd`,
///     `-f../../secret`) — many commands accept `-f<value>` as equivalent to `-f <value>`.
pub fn check_arg_path_safety(arg: &str) -> Result<(), String> {
    if arg.starts_with('-') {
        // Flags with `=`: check the value portion (e.g., --file=/etc/passwd, -f=../../secret)
        let has_eq = arg.find('=');
        if let Some(eq_pos) = has_eq {
            let value = &arg[eq_pos + 1..];
            if !value.is_empty() {
                return check_path_value(strip_quotes(value));
            }
        }
        // Short flags: after the leading `-` and flag letter(s), any remaining
        // characters are a concatenated value (e.g., `-f../../secret`).
        // Skip purely-alphabetic flag clusters like `-rn` or `-la`.
        if !arg.starts_with("--") && has_eq.is_none() {
            let after_dash = &arg[1..];
            // Find where the flag letters end and the value begins.
            // Flag letters are ASCII alphabetic; once we hit a non-alpha char
            // (/, ., digit for paths), that's the start of an embedded value.
            if let Some(value_start) = after_dash.find(|c: char| !c.is_ascii_alphabetic()) {
                let value = &after_dash[value_start..];
                if !value.is_empty() {
                    return check_path_value(strip_quotes(value));
                }
            }
        }
        return Ok(());
    }
    check_path_value(arg)
}

/// Check a path string for absolute paths and path traversal.
fn check_path_value(value: &str) -> Result<(), String> {
    if value.starts_with('/') {
        return Err(format!(
            "absolute path '{}' in argument not allowed",
            value
        ));
    }
    if value.split('/').any(|seg| seg == "..") {
        return Err(format!(
            "path traversal ('..') in argument '{}' not allowed",
            value
        ));
    }
    Ok(())
}

/// Check args against UNCONDITIONALLY_BLOCKED and PREFIX_BLOCKED for a command.
/// Used at validation time (on literal args) and at execution time (on expanded args)
/// to catch blocked flags like `find -delete` or `sort -o`.
pub fn check_blocked_flags(cmd: &str, args: &[&str]) -> Result<(), String> {
    if let Some((_, blocked_flags)) = UNCONDITIONALLY_BLOCKED.iter().find(|(c, _)| *c == cmd) {
        for arg in args {
            if blocked_flags.contains(arg) {
                return Err(format!("'{}' flag on '{}' is not allowed", arg, cmd));
            }
            // Catch blocked single-letter flags hidden in combined clusters:
            // e.g., `fd -Hx` is parsed by fd as `-H -x`, bypassing exact match on `-x`.
            if let Some(matched) = find_blocked_short_flag_in_cluster(arg, blocked_flags) {
                return Err(format!(
                    "'{}' flag on '{}' is not allowed (found in combined flags '{}')",
                    matched, cmd, arg
                ));
            }
        }
    }
    if let Some((_, blocked_prefixes)) = PREFIX_BLOCKED.iter().find(|(c, _)| *c == cmd) {
        for arg in args {
            for prefix in *blocked_prefixes {
                if arg.starts_with(prefix) {
                    return Err(format!(
                        "'{}' flag on '{}' is not allowed (writes files in place)",
                        arg, cmd
                    ));
                }
            }
            // Catch blocked single-letter prefix flags in combined clusters:
            // e.g., `sort -ro file` is parsed by sort as `-r -o file`, bypassing
            // the prefix check on `-o`.
            if let Some(matched) = find_blocked_short_flag_in_cluster(arg, blocked_prefixes) {
                return Err(format!(
                    "'{}' flag on '{}' is not allowed (writes files in place; found in combined flags '{}')",
                    matched, cmd, arg
                ));
            }
        }
    }
    Ok(())
}

/// Check if a combined short-flag cluster (e.g., `-Hx`, `-nro`) contains
/// any single-letter blocked flag (e.g., `-x` or `-o`).
///
/// Only examines args that look like pure flag clusters: start with `-` (not `--`),
/// at least 3 characters, and all characters after the dash are ASCII alphabetic.
/// This avoids false positives on flags with embedded values like `-t:` or `-n3`.
fn find_blocked_short_flag_in_cluster<'a>(arg: &str, blocked: &[&'a str]) -> Option<&'a str> {
    // Must be a short-flag group: starts with -, not --, at least 2 flag letters
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 3 {
        return None;
    }
    let after_dash = &arg[1..];
    // A pure flag cluster is all ASCII alphabetic (no embedded values like -n3 or -f/path)
    if !after_dash.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    for flag in blocked {
        // Only match single-letter short flags: exactly "-X" (2 chars, one dash + one letter)
        if flag.len() == 2 && flag.starts_with('-') {
            let blocked_char = flag.as_bytes()[1];
            if after_dash.as_bytes().contains(&blocked_char) {
                return Some(flag);
            }
        }
    }
    None
}

/// Convenience wrapper for `check_blocked_flags` when args are `&[String]`.
pub fn check_blocked_flags_expanded(cmd: &str, args: &[String]) -> Result<(), String> {
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    check_blocked_flags(cmd, &refs)
}

/// Check that a command name is present in the allowlist.
/// Used at validation time (on literal names) and at execution time (on expanded names).
pub fn check_command_allowed(
    name: &str,
    allowlist: &crate::allowlist::Allowlist,
) -> Result<(), String> {
    if !allowlist.is_allowed(name) {
        return Err(format!(
            "command '{}' not in allowlist (allowed: {})",
            name,
            allowlist.allowed_commands().join(", ")
        ));
    }
    Ok(())
}

/// Strip surrounding quotes from a Word.value (brush-parser preserves them).
fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return &s[1..s.len() - 1];
    }
    s
}
