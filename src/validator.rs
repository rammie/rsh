/// Recursive AST security walker for brush-parser ASTs.
///
/// Walks every node in a `brush_parser::ast::Program` and enforces:
/// - Command allowlist
/// - Blocked flags (-delete, -ok, -okdir, -exec, -execdir on find; -x/--exec on fd)
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
    ("find", &["-delete", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls", "-exec", "-execdir"]),
    ("fd", &["-x", "--exec", "-X", "--exec-batch"]),
];

/// Flags blocked by prefix match (e.g., sort -o, sort -ofoo all blocked).
const PREFIX_BLOCKED: &[(&str, &[&str])] = &[
    ("sort", &["-o", "--output"]),
];


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
        self.check_blocked_flags(&cmd_name, &string_args)?;

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
                        // Check iteration values for absolute paths and path traversal —
                        // otherwise an attacker can set a loop variable to an absolute path
                        // and use it in command arguments to bypass path restrictions.
                        self.check_arg_path(&w.value)?;
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

    /// Check args against UNCONDITIONALLY_BLOCKED and PREFIX_BLOCKED for a command.
    fn check_blocked_flags(&self, cmd: &str, args: &[&str]) -> Result<(), String> {
        if let Some((_, blocked_flags)) = UNCONDITIONALLY_BLOCKED.iter().find(|(c, _)| *c == cmd) {
            for arg in args {
                if blocked_flags.contains(arg) {
                    return Err(format!("'{}' flag on '{}' is not allowed", arg, cmd));
                }
            }
        }
        if let Some((_, blocked_prefixes)) = PREFIX_BLOCKED.iter().find(|(c, _)| *c == cmd) {
            for arg in args {
                for prefix in *blocked_prefixes {
                    if arg.starts_with(prefix) {
                        return Err(format!("'{}' flag on '{}' is not allowed (writes files in place)", arg, cmd));
                    }
                }
            }
        }
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
