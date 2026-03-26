/// Built-in restricted sed: only supports `-n` with address + `p` for line extraction.
///
/// This is a safe reimplementation — no exec, no scripting, no file writes.
/// Covers the primary LLM use case: `sed -n '10,20p' file`
use std::io::BufRead;
use std::path::Path;

#[derive(Debug)]
enum Addr {
    /// Single line: `5p`
    Line(usize),
    /// Last line: `$p`
    Last,
    /// Range: `10,20p` or `5,$p`
    Range(usize, RangeEnd),
}

#[derive(Debug)]
enum RangeEnd {
    Line(usize),
    Last,
}

/// Parse a single sed expression like "10p", "10,20p", "$p", "10,$p".
fn parse_expr(s: &str) -> Result<Addr, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty expression".to_string());
    }

    // Must end with 'p'
    if !s.ends_with('p') {
        let cmd = s.chars().last().unwrap();
        return Err(format!(
            "unsupported sed command '{}' — only 'p' (print) is allowed",
            cmd
        ));
    }
    let addr_str = &s[..s.len() - 1];

    if addr_str.is_empty() {
        return Err("missing address — use e.g. '10p' or '10,20p'".to_string());
    }

    // Check for range
    if let Some(comma_pos) = addr_str.find(',') {
        let start_str = &addr_str[..comma_pos];
        let end_str = &addr_str[comma_pos + 1..];

        let start = parse_line_number(start_str)?;

        let end = if end_str == "$" {
            RangeEnd::Last
        } else {
            let end_num = parse_line_number(end_str)?;
            if end_num < start {
                return Err(format!(
                    "inverted range {},{} — start must be <= end",
                    start, end_num
                ));
            }
            RangeEnd::Line(end_num)
        };

        Ok(Addr::Range(start, end))
    } else if addr_str == "$" {
        Ok(Addr::Last)
    } else {
        let n = parse_line_number(addr_str)?;
        Ok(Addr::Line(n))
    }
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
            for part in args[i].split(';') {
                let part = part.trim();
                if !part.is_empty() {
                    exprs.push(parse_expr(part)?);
                }
            }
        } else if arg.starts_with('-') {
            return Err(format!("unsupported sed flag '{}'", arg));
        } else if exprs.is_empty() {
            // First non-flag argument is the script (if no -e was used)
            for part in arg.split(';') {
                let part = part.trim();
                if !part.is_empty() {
                    exprs.push(parse_expr(part)?);
                }
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

/// Check if a line number matches any expression.
/// For `$p` and range-to-`$`, `is_last` indicates this is the final line.
fn line_matches(exprs: &[Addr], line_num: usize, is_last: bool) -> bool {
    exprs.iter().any(|addr| match addr {
        Addr::Line(n) => line_num == *n,
        Addr::Last => is_last,
        Addr::Range(start, end) => {
            let past_start = line_num >= *start;
            let before_end = match end {
                RangeEnd::Line(n) => line_num <= *n,
                RangeEnd::Last => true,
            };
            past_start && before_end
        }
    })
}

/// Returns true if any expression uses `$` (last-line addressing),
/// which requires reading the entire file to know the line count.
fn needs_last_line(exprs: &[Addr]) -> bool {
    exprs.iter().any(|addr| matches!(addr, Addr::Last | Addr::Range(_, RangeEnd::Last)))
}

/// Returns the maximum fixed line number referenced, for early exit optimization.
fn max_fixed_line(exprs: &[Addr]) -> Option<usize> {
    let mut max = None;
    for addr in exprs {
        match addr {
            Addr::Line(n) => {
                max = Some(max.map_or(*n, |m: usize| m.max(*n)));
            }
            Addr::Range(_, RangeEnd::Line(n)) => {
                max = Some(max.map_or(*n, |m: usize| m.max(*n)));
            }
            _ => return None, // has $ addressing, can't early-exit
        }
    }
    max
}

/// Execute the restricted sed builtin. Returns (stdout, stderr, exit_code).
pub fn execute(args: &[String], working_dir: &Path, stdin_data: Option<&str>) -> (String, String, i32) {
    let (exprs, files) = match parse_args(args) {
        Ok(v) => v,
        Err(e) => return (String::new(), format!("sed: {}\n", e), 1),
    };

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
    if needs_last_line(exprs) {
        let all: Vec<&str> = lines.collect();
        let total = all.len();
        for (i, line) in all.iter().enumerate() {
            let line_num = i + 1;
            if line_matches(exprs, line_num, line_num == total) {
                stdout.push_str(line);
                stdout.push('\n');
            }
        }
    } else {
        let max_line = max_fixed_line(exprs);
        for (i, line) in lines.enumerate() {
            let line_num = i + 1;
            if line_matches(exprs, line_num, false) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_line() {
        let addr = parse_expr("5p").unwrap();
        assert!(std::matches!(addr, Addr::Line(5)));
    }

    #[test]
    fn test_parse_last_line() {
        let addr = parse_expr("$p").unwrap();
        assert!(std::matches!(addr, Addr::Last));
    }

    #[test]
    fn test_parse_range() {
        let addr = parse_expr("10,20p").unwrap();
        assert!(std::matches!(addr, Addr::Range(10, RangeEnd::Line(20))));
    }

    #[test]
    fn test_parse_range_to_last() {
        let addr = parse_expr("5,$p").unwrap();
        assert!(std::matches!(addr, Addr::Range(5, RangeEnd::Last)));
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
    fn test_parse_missing_address() {
        let err = parse_expr("p").unwrap_err();
        assert!(err.contains("missing address"));
    }

    #[test]
    fn test_parse_bad_line_number() {
        let err = parse_expr("abcp").unwrap_err();
        assert!(err.contains("invalid line number"));
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
    fn test_parse_args_multiple_e() {
        let args: Vec<String> = vec!["-n".into(), "-e".into(), "5p".into(), "-e".into(), "10p".into(), "f.txt".into()];
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
    fn test_line_matches_single() {
        let addr = parse_expr("5p").unwrap();
        assert!(!line_matches(&[addr], 4, false));
        let addr = parse_expr("5p").unwrap();
        assert!(line_matches(&[addr], 5, false));
        let addr = parse_expr("5p").unwrap();
        assert!(!line_matches(&[addr], 6, false));
    }

    #[test]
    fn test_line_matches_range() {
        let addr = parse_expr("3,5p").unwrap();
        assert!(!line_matches(&[addr], 2, false));
        let addr = parse_expr("3,5p").unwrap();
        assert!(line_matches(&[addr], 3, false));
        let addr = parse_expr("3,5p").unwrap();
        assert!(line_matches(&[addr], 4, false));
        let addr = parse_expr("3,5p").unwrap();
        assert!(line_matches(&[addr], 5, false));
        let addr = parse_expr("3,5p").unwrap();
        assert!(!line_matches(&[addr], 6, false));
    }

    #[test]
    fn test_line_matches_last() {
        let addr = parse_expr("$p").unwrap();
        assert!(!line_matches(&[addr], 5, false));
        let addr = parse_expr("$p").unwrap();
        assert!(line_matches(&[addr], 5, true));
    }

    #[test]
    fn test_process_lines_basic() {
        let addr = parse_expr("2,3p").unwrap();
        let input = "line1\nline2\nline3\nline4";
        let mut out = String::new();
        process_lines(&[addr], input.lines(), &mut out);
        assert_eq!(out, "line2\nline3\n");
    }

    #[test]
    fn test_process_lines_last() {
        let addr = parse_expr("$p").unwrap();
        let input = "line1\nline2\nline3";
        let mut out = String::new();
        process_lines(&[addr], input.lines(), &mut out);
        assert_eq!(out, "line3\n");
    }

    #[test]
    fn test_process_lines_range_to_last() {
        let addr = parse_expr("2,$p").unwrap();
        let input = "line1\nline2\nline3";
        let mut out = String::new();
        process_lines(&[addr], input.lines(), &mut out);
        assert_eq!(out, "line2\nline3\n");
    }

    #[test]
    fn test_unsupported_flag() {
        let args: Vec<String> = vec!["-n".into(), "-i".into(), "5p".into()];
        let err = parse_args(&args).unwrap_err();
        assert!(err.contains("unsupported sed flag"));
    }
}
