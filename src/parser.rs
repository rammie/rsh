/// Hand-written recursive descent parser for the restricted shell grammar.
///
/// Grammar:
///   program   := pipeline (';' pipeline)* ';'?
///   pipeline  := command ('|' command)*
///   command   := IDENT arg* redirect*
///   arg       := BARE | SINGLE_QUOTED | DOUBLE_QUOTED | VAR
///   redirect  := ('>' | '>>') PATH
///   VAR       := '$' IDENT | '${' IDENT '}'

use crate::ast::*;

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "parse error at position {}: {}", self.position, self.message)
    }
}

pub fn parse(input: &str) -> Result<Program, ParseError> {
    let mut parser = Parser::new(input);
    parser.parse_program()
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn error(&self, msg: impl Into<String>) -> ParseError {
        ParseError {
            message: msg.into(),
            position: self.pos,
        }
    }

    fn parse_program(&mut self) -> Result<Program, ParseError> {
        let mut pipelines = Vec::new();
        self.skip_whitespace();

        while !self.at_end() {
            let pipeline = self.parse_pipeline()?;
            pipelines.push(pipeline);
            self.skip_whitespace();

            // Allow optional semicolons between pipelines
            if self.peek() == Some(';') {
                self.advance();
                self.skip_whitespace();
            }
        }

        if pipelines.is_empty() {
            return Err(self.error("empty input"));
        }

        Ok(Program { pipelines })
    }

    fn parse_pipeline(&mut self) -> Result<Pipeline, ParseError> {
        let mut commands = Vec::new();
        commands.push(self.parse_command()?);

        loop {
            self.skip_whitespace();
            if self.remaining().starts_with("&&") {
                return Err(self.error("'&&' (logical AND) is not supported"));
            }
            if self.peek() == Some('|') {
                // Make sure it's not ||
                if self.remaining().starts_with("||") {
                    return Err(self.error("'||' (logical OR) is not supported"));
                }
                self.advance(); // consume '|'
                self.skip_whitespace();
                commands.push(self.parse_command()?);
            } else {
                break;
            }
        }

        Ok(Pipeline { commands })
    }

    fn parse_command(&mut self) -> Result<Command, ParseError> {
        self.skip_whitespace();

        let name = self.parse_bare_word()?;
        if name.is_empty() {
            return Err(self.error("expected command name"));
        }

        let mut args = Vec::new();
        let mut redirects = Vec::new();

        loop {
            self.skip_whitespace();

            match self.peek() {
                None | Some('|') | Some(';') => break,
                Some('>') => {
                    redirects.push(self.parse_redirect()?);
                }
                Some('`') => {
                    return Err(self.error("backtick command substitution is not supported"));
                }
                Some('<') => {
                    if self.remaining().starts_with("<(") {
                        return Err(self.error("'<()' process substitution is not supported"));
                    }
                    return Err(self.error("input redirection is not supported"));
                }
                Some('(') => {
                    return Err(self.error("subshells are not supported"));
                }
                Some('&') => {
                    if self.remaining().starts_with("&&") {
                        return Err(self.error("'&&' (logical AND) is not supported"));
                    }
                    return Err(self.error("background execution (&) is not supported"));
                }
                Some(_) => {
                    args.push(self.parse_arg()?);
                }
            }
        }

        Ok(Command { name, args, redirects })
    }

    fn parse_arg(&mut self) -> Result<Arg, ParseError> {
        match self.peek() {
            Some('\'') => self.parse_single_quoted(),
            Some('"') => self.parse_double_quoted(),
            Some('$') => self.parse_var(),
            Some(_) => {
                let word = self.parse_bare_word()?;
                // Check if it's a bare $VAR that got parsed as a word
                if word.starts_with('$') {
                    Ok(Arg::Var(word[1..].to_string()))
                } else {
                    Ok(Arg::Bare(word))
                }
            }
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn parse_bare_word(&mut self) -> Result<String, ParseError> {
        let mut word = String::new();
        while let Some(ch) = self.peek() {
            match ch {
                ' ' | '\t' | '|' | ';' | '\n' | '\'' | '"' | '&' | '`' | '<' | '(' | ')' => break,
                '>' => {
                    // Could be redirect — stop bare word
                    break;
                }
                '\\' => {
                    // Escape next char
                    self.advance();
                    if let Some(next) = self.advance() {
                        word.push(next);
                    } else {
                        return Err(self.error("unexpected end of input after backslash"));
                    }
                }
                _ => {
                    word.push(ch);
                    self.advance();
                }
            }
        }
        Ok(word)
    }

    fn parse_single_quoted(&mut self) -> Result<Arg, ParseError> {
        assert_eq!(self.advance(), Some('\'')); // consume opening quote
        let mut s = String::new();
        loop {
            match self.advance() {
                Some('\'') => return Ok(Arg::SingleQuoted(s)),
                Some(ch) => s.push(ch),
                None => return Err(self.error("unterminated single-quoted string")),
            }
        }
    }

    fn parse_double_quoted(&mut self) -> Result<Arg, ParseError> {
        assert_eq!(self.advance(), Some('"')); // consume opening quote
        let mut s = String::new();
        loop {
            match self.advance() {
                Some('"') => return Ok(Arg::DoubleQuoted(s)),
                Some('\\') => {
                    match self.advance() {
                        Some(ch) => s.push(ch),
                        None => return Err(self.error("unterminated escape in double-quoted string")),
                    }
                }
                Some(ch) => s.push(ch),
                None => return Err(self.error("unterminated double-quoted string")),
            }
        }
    }

    fn parse_var(&mut self) -> Result<Arg, ParseError> {
        assert_eq!(self.advance(), Some('$')); // consume $

        if self.peek() == Some('(') {
            return Err(self.error("'$()' command substitution is not supported"));
        }

        if self.peek() == Some('{') {
            self.advance(); // consume {
            let mut name = String::new();
            loop {
                match self.advance() {
                    Some('}') => return Ok(Arg::Var(name)),
                    Some(ch) if ch.is_alphanumeric() || ch == '_' => name.push(ch),
                    Some(ch) => return Err(self.error(format!("unexpected character '{}' in variable name", ch))),
                    None => return Err(self.error("unterminated ${...} variable")),
                }
            }
        }

        // Simple $IDENT
        let mut name = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                name.push(ch);
                self.advance();
            } else {
                break;
            }
        }

        if name.is_empty() {
            return Err(self.error("expected variable name after $"));
        }

        Ok(Arg::Var(name))
    }

    fn parse_redirect(&mut self) -> Result<Redirect, ParseError> {
        let start = self.pos;
        assert_eq!(self.advance(), Some('>')); // consume first >

        let kind = if self.peek() == Some('>') {
            self.advance();
            // Check for >(
            if self.peek() == Some('(') {
                return Err(ParseError {
                    message: "'>()' process substitution is not supported".into(),
                    position: start,
                });
            }
            RedirectKind::Append
        } else {
            if self.peek() == Some('(') {
                return Err(ParseError {
                    message: "'>()' process substitution is not supported".into(),
                    position: start,
                });
            }
            RedirectKind::Overwrite
        };

        self.skip_whitespace();

        let target = self.parse_bare_word()?;
        if target.is_empty() {
            return Err(self.error("expected file path after redirect"));
        }

        Ok(Redirect { kind, target })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let prog = parse("ls -la").unwrap();
        assert_eq!(prog.pipelines.len(), 1);
        let cmd = &prog.pipelines[0].commands[0];
        assert_eq!(cmd.name, "ls");
        assert_eq!(cmd.args, vec![Arg::Bare("-la".into())]);
    }

    #[test]
    fn test_pipeline() {
        let prog = parse("grep foo | head -n 5").unwrap();
        assert_eq!(prog.pipelines[0].commands.len(), 2);
        assert_eq!(prog.pipelines[0].commands[0].name, "grep");
        assert_eq!(prog.pipelines[0].commands[1].name, "head");
    }

    #[test]
    fn test_quoted_strings() {
        let prog = parse(r#"grep "hello world" 'single'"#).unwrap();
        let cmd = &prog.pipelines[0].commands[0];
        assert_eq!(cmd.args[0], Arg::DoubleQuoted("hello world".into()));
        assert_eq!(cmd.args[1], Arg::SingleQuoted("single".into()));
    }

    #[test]
    fn test_variable() {
        let prog = parse("echo $HOME ${PATH}").unwrap();
        let cmd = &prog.pipelines[0].commands[0];
        assert_eq!(cmd.args[0], Arg::Var("HOME".into()));
        assert_eq!(cmd.args[1], Arg::Var("PATH".into()));
    }

    #[test]
    fn test_redirect() {
        let prog = parse("echo hello > /tmp/out").unwrap();
        let cmd = &prog.pipelines[0].commands[0];
        assert_eq!(cmd.redirects.len(), 1);
        assert_eq!(cmd.redirects[0].kind, RedirectKind::Overwrite);
        assert_eq!(cmd.redirects[0].target, "/tmp/out");
    }

    #[test]
    fn test_reject_and_or() {
        assert!(parse("ls && echo hi").is_err());
        assert!(parse("ls || echo hi").is_err());
    }

    #[test]
    fn test_reject_command_substitution() {
        assert!(parse("echo $(whoami)").is_err());
    }

    #[test]
    fn test_reject_backticks() {
        assert!(parse("echo `whoami`").is_err());
    }

    #[test]
    fn test_keywords_in_quotes_allowed() {
        // Keywords inside quotes should NOT be rejected
        let prog = parse("grep 'if' file").unwrap();
        assert_eq!(prog.pipelines[0].commands[0].name, "grep");
    }

    #[test]
    fn test_and_in_quotes_allowed() {
        let prog = parse("grep '&&' file").unwrap();
        assert_eq!(prog.pipelines[0].commands[0].name, "grep");
    }

    #[test]
    fn test_semicolons() {
        let prog = parse("ls; pwd").unwrap();
        assert_eq!(prog.pipelines.len(), 2);
    }
}
