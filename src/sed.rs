/// Built-in restricted sed: supports `-n` with address + `p` for line extraction.
///
/// This is a safe reimplementation — no exec, no scripting, no file writes.
/// Supports line-number addresses (`sed -n '10,20p'`) and regex addresses
/// (`sed -n '/pattern/p'`), including mixed ranges.
use regex::Regex;
use std::borrow::Cow;
use std::io::BufRead;
use std::path::Path;

use crate::validator;

/// A single address specification: line number, last line, or regex pattern.
#[derive(Debug)]
enum AddrSpec {
    Line(usize),
    Last,
    Pattern(Regex),
}

/// A full address expression with command `p`.
#[derive(Debug)]
enum Addr {
    Single(AddrSpec),
    Range(AddrSpec, AddrSpec),
}

/// Try to parse a `/regex/` at the start of `s`. Returns (Regex, rest_of_string).
fn parse_regex_addr(s: &str) -> Result<(Regex, &str), String> {
    debug_assert!(s.starts_with('/'));
    let inner = &s[1..];
    // Find the closing `/`, handling `\/` escapes.
    let mut i = 0;
    let bytes = inner.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped char
            continue;
        }
        if bytes[i] == b'/' {
            let pattern = &inner[..i];
            let unescaped: Cow<str> = if pattern.contains("\\/") {
                pattern.replace("\\/", "/").into()
            } else {
                pattern.into()
            };
            let re = Regex::new(&unescaped)
                .map_err(|e| format!("invalid regex '{}': {}", pattern, e))?;
            let rest = &inner[i + 1..];
            return Ok((re, rest));
        }
        i += 1;
    }
    Err(format!("unterminated regex address '/{}'", inner))
}

/// Parse a single address spec (line number, `$`, or `/regex/`) from the front
/// of `s`. Returns (AddrSpec, remaining_str).
fn parse_addr_spec(s: &str) -> Result<(AddrSpec, &str), String> {
    if s.starts_with('/') {
        let (re, rest) = parse_regex_addr(s)?;
        Ok((AddrSpec::Pattern(re), rest))
    } else if s.starts_with('$') {
        Ok((AddrSpec::Last, &s[1..]))
    } else {
        // Consume digits.
        let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        if end == 0 {
            return Err(format!("expected address, got '{}'", s));
        }
        let n = parse_line_number(&s[..end])?;
        Ok((AddrSpec::Line(n), &s[end..]))
    }
}

/// Parse a single sed expression like "10p", "/pattern/p", "10,/end/p", etc.
fn parse_expr(s: &str) -> Result<Addr, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty expression".to_string());
    }

    let (first, rest) = parse_addr_spec(s)?;

    if let Some(rest) = rest.strip_prefix(',') {
        // Range expression.
        let (second, rest2) = parse_addr_spec(rest)?;

        // Validate inverted line-number ranges.
        if let (AddrSpec::Line(a), AddrSpec::Line(b)) = (&first, &second) {
            if b < a {
                return Err(format!("inverted range {},{} — start must be <= end", a, b));
            }
        }

        require_p_command(rest2)?;
        Ok(Addr::Range(first, second))
    } else {
        require_p_command(rest)?;
        Ok(Addr::Single(first))
    }
}

fn require_p_command(rest: &str) -> Result<(), String> {
    if rest == "p" {
        return Ok(());
    }
    if rest.is_empty() {
        return Err("missing command — use e.g. '10,20p' or '/pattern/p'".to_string());
    }
    let cmd = rest.chars().next().unwrap();
    Err(format!(
        "unsupported sed command '{}' — only 'p' (print) is allowed",
        cmd
    ))
}

fn parse_line_number(s: &str) -> Result<usize, String> {
    let n = s
        .parse::<usize>()
        .map_err(|_| format!("invalid line number '{}'", s))?;
    if n == 0 {
        return Err("line numbers start at 1, not 0".to_string());
    }
    Ok(n)
}

/// Parse the full sed argument list. Returns (expressions, files).
fn parse_args(args: &[String]) -> Result<(Vec<Addr>, Vec<String>), String> {
    let mut exprs = Vec::new();
    let mut files = Vec::new();
    let mut has_n = false;
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        if arg == "-n" {
            has_n = true;
        } else if arg == "-e" {
            i += 1;
            if i >= args.len() {
                return Err("-e requires an expression".to_string());
            }
            for part in split_expressions(&args[i]) {
                exprs.push(parse_expr(&part)?);
            }
        } else if arg.starts_with('-') {
            return Err(format!("unsupported sed flag '{}'", arg));
        } else if exprs.is_empty() {
            // First non-flag argument is the script (if no -e was used)
            for part in split_expressions(arg) {
                exprs.push(parse_expr(&part)?);
            }
        } else {
            files.push(arg.clone());
        }
        i += 1;
    }

    if !has_n {
        return Err("sed requires -n flag (only print-mode is supported)".to_string());
    }

    if exprs.is_empty() {
        return Err("no sed expression provided".to_string());
    }

    Ok((exprs, files))
}

/// Split a sed script on `;`, respecting `/regex/` delimiters.
/// e.g. `"/foo/p;10,20p"` → `["/foo/p", "10,20p"]`
fn split_expressions(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_regex = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            current.push(c as char);
            current.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if c == b'/' {
            in_regex = !in_regex;
            current.push(c as char);
        } else if c == b';' && !in_regex {
            if !current.is_empty() {
                parts.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c as char);
        }
        i += 1;
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Check if a line matches a single address spec.
fn addr_spec_matches(spec: &AddrSpec, line: &str, line_num: usize, is_last: bool) -> bool {
    match spec {
        AddrSpec::Line(n) => line_num == *n,
        AddrSpec::Last => is_last,
        AddrSpec::Pattern(re) => re.is_match(line),
    }
}

/// Returns true if any expression uses `$` (last-line addressing),
/// which requires reading the entire input to know the line count.
/// Regex patterns do NOT require full scan — they can stream.
fn needs_full_scan(exprs: &[Addr]) -> bool {
    exprs.iter().any(|addr| match addr {
        Addr::Single(AddrSpec::Last) => true,
        Addr::Range(AddrSpec::Last, _) | Addr::Range(_, AddrSpec::Last) => true,
        _ => false,
    })
}

/// Returns the maximum fixed line number referenced, for early exit optimization.
/// Only returns Some when ALL expressions use pure line-number addressing.
fn max_fixed_line(exprs: &[Addr]) -> Option<usize> {
    let mut max = None;
    for addr in exprs {
        match addr {
            Addr::Single(AddrSpec::Line(n)) => {
                max = Some(max.map_or(*n, |m: usize| m.max(*n)));
            }
            Addr::Range(_, AddrSpec::Line(n)) => {
                max = Some(max.map_or(*n, |m: usize| m.max(*n)));
            }
            _ => return None,
        }
    }
    max
}

/// Execute the restricted sed builtin. Returns (stdout, stderr, exit_code).
pub fn execute(
    args: &[String],
    working_dir: &Path,
    stdin_data: Option<&str>,
) -> (String, String, i32) {
    let (exprs, files) = match parse_args(args) {
        Ok(v) => v,
        Err(e) => return (String::new(), format!("sed: {}\n", e), 1),
    };

    // Validate file arguments for path safety (absolute paths, traversal).
    // The executor skips its blanket check for builtins, so we do it here
    // for file args only — expression args like `/pattern/p` are not paths.
    for file in &files {
        if let Err(e) = validator::check_arg_path_safety(file) {
            return (String::new(), format!("sed: {}\n", e), 1);
        }
    }

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0;

    if files.is_empty() {
        // Read from stdin
        match stdin_data {
            Some(data) => {
                process_lines(&exprs, data.lines(), &mut stdout);
            }
            None => {
                stderr.push_str("sed: no input files\n");
                exit_code = 1;
            }
        }
    } else {
        for file in &files {
            let path = working_dir.join(file);
            match std::fs::File::open(&path) {
                Ok(f) => {
                    let reader = std::io::BufReader::new(f);
                    let mut lines = Vec::new();
                    for line_result in reader.lines() {
                        match line_result {
                            Ok(line) => lines.push(line),
                            Err(e) => {
                                stderr.push_str(&format!("sed: {}: {}\n", file, e));
                                break;
                            }
                        }
                    }
                    process_lines(&exprs, lines.iter().map(|s| s.as_str()), &mut stdout);
                }
                Err(e) => {
                    stderr.push_str(&format!("sed: {}: {}\n", file, e));
                    exit_code = 2;
                }
            }
        }
    }

    (stdout, stderr, exit_code)
}

/// Process an iterator of lines against expressions, appending matches to stdout.
fn process_lines<'a, I: Iterator<Item = &'a str>>(exprs: &[Addr], lines: I, stdout: &mut String) {
    if needs_full_scan(exprs) {
        let all: Vec<&str> = lines.collect();
        let total = all.len();

        // Track range state: for each range expression, whether we're inside it.
        let mut range_active: Vec<bool> = exprs.iter().map(|_| false).collect();

        for (i, line) in all.iter().enumerate() {
            let line_num = i + 1;
            let is_last = line_num == total;
            if line_matches_any(exprs, &mut range_active, line, line_num, is_last) {
                stdout.push_str(line);
                stdout.push('\n');
            }
        }
    } else {
        let max_line = max_fixed_line(exprs);
        let mut range_active: Vec<bool> = exprs.iter().map(|_| false).collect();
        for (i, line) in lines.enumerate() {
            let line_num = i + 1;
            if line_matches_any(exprs, &mut range_active, line, line_num, false) {
                stdout.push_str(line);
                stdout.push('\n');
            }
            if let Some(max) = max_line {
                if line_num >= max {
                    break;
                }
            }
        }
    }
}

/// Check if a line matches any expression, tracking range state.
fn line_matches_any(
    exprs: &[Addr],
    range_active: &mut [bool],
    line: &str,
    line_num: usize,
    is_last: bool,
) -> bool {
    let mut matched = false;
    for (idx, addr) in exprs.iter().enumerate() {
        match addr {
            Addr::Single(spec) => {
                if addr_spec_matches(spec, line, line_num, is_last) {
                    matched = true;
                }
            }
            Addr::Range(start, end) => {
                if range_active[idx] {
                    // We're inside the range; check if this line ends it.
                    matched = true;
                    if addr_spec_matches(end, line, line_num, is_last) {
                        range_active[idx] = false;
                    }
                } else if addr_spec_matches(start, line, line_num, is_last) {
                    // Start of range.
                    matched = true;
                    range_active[idx] = true;
                    // Check if end also matches this same line (single-line range).
                    if addr_spec_matches(end, line, line_num, is_last) {
                        range_active[idx] = false;
                    }
                }
            }
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_line() {
        let addr = parse_expr("5p").unwrap();
        assert!(matches!(addr, Addr::Single(AddrSpec::Line(5))));
    }

    #[test]
    fn test_parse_last_line() {
        let addr = parse_expr("$p").unwrap();
        assert!(matches!(addr, Addr::Single(AddrSpec::Last)));
    }

    #[test]
    fn test_parse_range() {
        let addr = parse_expr("10,20p").unwrap();
        assert!(matches!(
            addr,
            Addr::Range(AddrSpec::Line(10), AddrSpec::Line(20))
        ));
    }

    #[test]
    fn test_parse_range_to_last() {
        let addr = parse_expr("5,$p").unwrap();
        assert!(matches!(
            addr,
            Addr::Range(AddrSpec::Line(5), AddrSpec::Last)
        ));
    }

    #[test]
    fn test_parse_regex_single() {
        let addr = parse_expr("/foo/p").unwrap();
        assert!(matches!(addr, Addr::Single(AddrSpec::Pattern(_))));
    }

    #[test]
    fn test_parse_regex_range() {
        let addr = parse_expr("/start/,/end/p").unwrap();
        assert!(matches!(
            addr,
            Addr::Range(AddrSpec::Pattern(_), AddrSpec::Pattern(_))
        ));
    }

    #[test]
    fn test_parse_mixed_line_regex_range() {
        let addr = parse_expr("5,/end/p").unwrap();
        assert!(matches!(
            addr,
            Addr::Range(AddrSpec::Line(5), AddrSpec::Pattern(_))
        ));
    }

    #[test]
    fn test_parse_mixed_regex_line_range() {
        let addr = parse_expr("/start/,10p").unwrap();
        assert!(matches!(
            addr,
            Addr::Range(AddrSpec::Pattern(_), AddrSpec::Line(10))
        ));
    }

    #[test]
    fn test_parse_regex_with_escaped_slash() {
        let addr = parse_expr("/foo\\/bar/p").unwrap();
        assert!(matches!(addr, Addr::Single(AddrSpec::Pattern(_))));
    }

    #[test]
    fn test_parse_no_p_command() {
        let err = parse_expr("10d").unwrap_err();
        assert!(err.contains("unsupported sed command"));
    }

    #[test]
    fn test_parse_empty() {
        let err = parse_expr("").unwrap_err();
        assert!(err.contains("empty expression"));
    }

    #[test]
    fn test_parse_missing_command() {
        let err = parse_expr("/pattern/").unwrap_err();
        assert!(err.contains("missing command"));
    }

    #[test]
    fn test_parse_bad_line_number() {
        let err = parse_expr("abcp").unwrap_err();
        assert!(err.contains("expected address"));
    }

    #[test]
    fn test_parse_line_zero_rejected() {
        let err = parse_expr("0p").unwrap_err();
        assert!(err.contains("start at 1"));
    }

    #[test]
    fn test_parse_inverted_range_rejected() {
        let err = parse_expr("5,3p").unwrap_err();
        assert!(err.contains("inverted range"));
    }

    #[test]
    fn test_parse_unterminated_regex() {
        let err = parse_expr("/unterminated").unwrap_err();
        assert!(err.contains("unterminated regex"));
    }

    #[test]
    fn test_parse_invalid_regex() {
        let err = parse_expr("/[invalid/p").unwrap_err();
        assert!(err.contains("invalid regex"));
    }

    #[test]
    fn test_parse_args_requires_n() {
        let args: Vec<String> = vec!["5p".into(), "file.txt".into()];
        let err = parse_args(&args).unwrap_err();
        assert!(err.contains("requires -n"));
    }

    #[test]
    fn test_parse_args_basic() {
        let args: Vec<String> = vec!["-n".into(), "5,10p".into(), "file.txt".into()];
        let (exprs, files) = parse_args(&args).unwrap();
        assert_eq!(exprs.len(), 1);
        assert_eq!(files, vec!["file.txt"]);
    }

    #[test]
    fn test_parse_args_regex() {
        let args: Vec<String> = vec!["-n".into(), "/pattern/p".into(), "file.txt".into()];
        let (exprs, files) = parse_args(&args).unwrap();
        assert_eq!(exprs.len(), 1);
        assert_eq!(files, vec!["file.txt"]);
    }

    #[test]
    fn test_parse_args_multiple_e() {
        let args: Vec<String> = vec![
            "-n".into(),
            "-e".into(),
            "5p".into(),
            "-e".into(),
            "10p".into(),
            "f.txt".into(),
        ];
        let (exprs, files) = parse_args(&args).unwrap();
        assert_eq!(exprs.len(), 2);
        assert_eq!(files, vec!["f.txt"]);
    }

    #[test]
    fn test_parse_args_semicolons() {
        let args: Vec<String> = vec!["-n".into(), "5p;10,20p".into(), "file.txt".into()];
        let (exprs, _) = parse_args(&args).unwrap();
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn test_parse_args_semicolons_with_regex() {
        let args: Vec<String> = vec!["-n".into(), "/foo/p;10,20p".into(), "file.txt".into()];
        let (exprs, _) = parse_args(&args).unwrap();
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn test_process_lines_basic() {
        let exprs = vec![parse_expr("2,3p").unwrap()];
        let input = "line1\nline2\nline3\nline4";
        let mut out = String::new();
        process_lines(&exprs, input.lines(), &mut out);
        assert_eq!(out, "line2\nline3\n");
    }

    #[test]
    fn test_process_lines_last() {
        let exprs = vec![parse_expr("$p").unwrap()];
        let input = "line1\nline2\nline3";
        let mut out = String::new();
        process_lines(&exprs, input.lines(), &mut out);
        assert_eq!(out, "line3\n");
    }

    #[test]
    fn test_process_lines_range_to_last() {
        let exprs = vec![parse_expr("2,$p").unwrap()];
        let input = "line1\nline2\nline3";
        let mut out = String::new();
        process_lines(&exprs, input.lines(), &mut out);
        assert_eq!(out, "line2\nline3\n");
    }

    #[test]
    fn test_process_lines_regex_single() {
        let exprs = vec![parse_expr("/two/p").unwrap()];
        let input = "one\ntwo\nthree\ntwo again";
        let mut out = String::new();
        process_lines(&exprs, input.lines(), &mut out);
        assert_eq!(out, "two\ntwo again\n");
    }

    #[test]
    fn test_process_lines_regex_range() {
        let exprs = vec![parse_expr("/START/,/END/p").unwrap()];
        let input = "before\nSTART here\nmiddle\nEND here\nafter";
        let mut out = String::new();
        process_lines(&exprs, input.lines(), &mut out);
        assert_eq!(out, "START here\nmiddle\nEND here\n");
    }

    #[test]
    fn test_process_lines_mixed_line_regex_range() {
        let exprs = vec![parse_expr("2,/end/p").unwrap()];
        let input = "one\ntwo\nthree\nend here\nfive";
        let mut out = String::new();
        process_lines(&exprs, input.lines(), &mut out);
        assert_eq!(out, "two\nthree\nend here\n");
    }

    #[test]
    fn test_process_lines_regex_line_range() {
        let exprs = vec![parse_expr("/start/,3p").unwrap()];
        let input = "one\nstart here\nthree\nfour";
        let mut out = String::new();
        process_lines(&exprs, input.lines(), &mut out);
        assert_eq!(out, "start here\nthree\n");
    }

    #[test]
    fn test_split_expressions_with_regex() {
        let parts = split_expressions("/foo/p;10,20p");
        assert_eq!(parts, vec!["/foo/p", "10,20p"]);
    }

    #[test]
    fn test_split_expressions_regex_with_semicolon_inside() {
        // A semicolon inside /regex;here/ should NOT split.
        let parts = split_expressions("/foo;bar/p");
        assert_eq!(parts, vec!["/foo;bar/p"]);
    }

    #[test]
    fn test_unsupported_flag() {
        let args: Vec<String> = vec!["-n".into(), "-i".into(), "5p".into()];
        let err = parse_args(&args).unwrap_err();
        assert!(err.contains("unsupported sed flag"));
    }

    #[test]
    fn test_file_path_safety_absolute() {
        let args = &["-n".into(), "1p".into(), "/etc/passwd".into()];
        let (_, _, exit) = execute(args, Path::new("."), None);
        assert_ne!(exit, 0);
    }

    #[test]
    fn test_file_path_safety_traversal() {
        let args = &["-n".into(), "1p".into(), "../secret".into()];
        let (_, stderr, exit) = execute(args, Path::new("."), None);
        assert_ne!(exit, 0);
        assert!(stderr.contains("path traversal"));
    }
}
