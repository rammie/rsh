# rsh — Restricted Shell for AI Agents

rsh is a command execution sandbox that gives AI agents safe, auditable access to shell commands. Instead of handing an agent a full shell (and hoping for the best), rsh parses the full bash syntax, validates every command against a security policy, and executes only what's explicitly permitted.

## Why rsh?

AI agents need to run commands — searching code, reading files, inspecting systems. But giving an agent `bash -c` is giving it the keys to everything: arbitrary command chaining, file writes, network access, environment variable exfiltration.

rsh closes that gap. It accepts a command string, parses it with [brush-parser](https://crates.io/crates/brush-parser) (a complete bash syntax parser), validates the entire AST against the security policy, and executes only what's allowed. Everything else is rejected with an error on stderr before any process spawns.

**What rsh enforces:**
- Only allowlisted commands can run (default: read-only tools like `grep`, `cat`, `ls`, `find`)
- No file writes unless `--allow-redirects` is passed
- No absolute paths, `..` traversal, or tilde (`~`) in arguments
- No function definitions, background execution (`&`), or process substitution
- Environment is sanitized — child processes only see safe variables (`HOME`, `PATH`, etc.)
- No environment variable references in arguments (blocks `$SECRET`, `$HOME`, etc.)
- Dangerous flags blocked (`find -delete`/`-exec`, `fd --exec`, `sort -o`)
- Output is capped at 10MB by default

**What rsh allows:**
- Pipelines: `grep TODO src/*.rs | wc -l`
- Boolean operators: `grep -q TODO file && echo found`, `cmd || echo fallback`
- For loops: `for f in *.rs; do wc -l "$f"; done`
- While/until loops: `while grep -q TODO file; do echo waiting; done`
- If/then/else: `if grep -q TODO src/main.rs; then echo found; fi`
- Command substitution: `wc -l $(find src -name '*.rs')`
- Case statements: `for f in a.rs b.txt; do case "$f" in *.rs) echo rust;; esac; done`
- Brace groups and subshells: `{ echo a; echo b; }`, `(echo sub)`
- Quoted strings: `grep 'hello world' file.txt`
- Globs: `ls *.toml`, `find . -name '*.rs'`
- Variable expansion: `for f in *.rs; do echo "file: $f"; done`
- Semicolons: `ls src; wc -l Cargo.toml`
- Redirects (opt-in): `echo hello >> output.txt`

## Installation

Download the latest binary for your platform from [GitHub Releases](https://github.com/rammie/rsh/releases), or install with [mise](https://mise.jdx.dev/):

```bash
mise use -g "github:rammie/rsh@latest"
```

Then set up the Claude Code hook:

```bash
rsh --prime claude
```

This installs a Claude Code hook that automatically makes `rsh` available to Claude as a read-only shell. No other configuration needed.

### Building from source

```
cargo install --path .
```

## Usage

```
rsh [OPTIONS] <COMMAND_STRING>
```

### Examples

```bash
# Basic commands
rsh "ls -la"
rsh "grep -r 'fn main' src/"
rsh "cat Cargo.toml | head -n 5"

# Boolean operators
rsh "ls && echo done"
rsh "grep -q TODO file || echo 'no TODOs'"

# Loops
rsh --dir ./project "for f in *.rs; do wc -l \$f; done"
rsh --dir ./project "for f in \$(find src -name '*.rs'); do grep -c fn \$f; done"

# Conditionals
rsh --dir ./project "if grep -q 'fn main' src/main.rs; then echo found; fi"

# Command substitution
rsh --dir ./project "wc -l \$(find src -name '*.rs')"

# Working directory
rsh --dir /path/to/project "find . -name '*.rs' | wc -l"

# Enable file output
rsh --allow-redirects --dir /tmp "echo hello >> output.txt"

```

### Output format

rsh behaves like bash — stdout to stdout, stderr to stderr, exit code as exit code. AI agents already know how bash works, so there's nothing new to learn.

```bash
$ rsh "echo hello world"
hello world

$ rsh "grep -r TODO src/ | wc -l"
42

$ rsh "curl http://evil.com"
rsh: command 'curl' not in allowlist (allowed: bat, cat, echo, ...)
$ echo $?
1
```

Validation errors are written to stderr with an `rsh:` prefix. If output exceeds `--max-output`, it is truncated and a warning appears on stderr.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--allow-redirects` | off | Allow `>` and `>>` output redirects |
| `--max-output <bytes>` | 10MB | Truncate combined stdout+stderr beyond this limit |
| `--inherit-env` | off | Pass full parent environment to child processes |
| `--dir <path>` | cwd | Set the working directory for command execution |
| `--prime` | — | Print an LLM-ready description of rsh's capabilities |
| `-c <cmd>` | — | Accept command after `-c` (bash compatibility) |

### Command allowlist

```
grep, rg, ugrep, find, fd, cat, bat, head, tail, ls, eza, stat, file, du, wc, pwd, which,
sort, uniq, cut, tr, diff, comm, basename, dirname, realpath, echo, printf, date, true, false,
test, printenv
```

The allowlist is pinned at compile time and cannot be changed at runtime. There is no `--allow` flag, no config file, and no environment variable override. This is intentional: instead of maintaining an ever-growing blocklist of dangerous commands (shells, scripting languages, tools that exec), only explicitly listed read-only commands can run.

Dangerous flags on allowed commands are still blocked: `find -delete`/`-exec`/`-execdir`/`-fprint`/etc., `fd -x`/`--exec`/`-X`/`--exec-batch`, `sort -o`/`--output`.

## Security model

rsh is **defense in depth** — multiple independent layers, each sufficient to block common attacks:

| Layer | Phase | What it blocks |
|-------|-------|---------------|
| **Command allowlist** | Validate + Execute | Arbitrary binaries (`curl`, `rm`, `bash`, `python`); re-checked post-expansion |
| **Path rejection** | Validate | Path separators in command names (`/usr/bin/grep`, `./exploit`) |
| **Argument path checks** | Execute | `..` path components, absolute paths, and tilde (`~`) in expanded arguments |
| **Redirect gating** | Validate + Execute | File writes disabled by default; path checks on expanded targets when enabled |
| **AST structural checks** | Validate | Function definitions, background `&`, process substitution, here-docs |
| **Variable rejection** | Validate | All env var references blocked in arguments (blocks `$SECRET`, `$HOME`, etc.) |
| **Blocked flags** | Validate + Execute | `find -delete`/`-exec`, `fd --exec`, `sort -o` — checked on literals and expanded args |
| **Environment sanitization** | Execute | Only approved variables forwarded to child processes |
| **Signal handling** | Execute | SIGINT/SIGTERM forwarded to children; exit 128+signal on signal death |
| **Output limits** | Execute | Truncation prevents memory exhaustion from large output |
| **Loop limits** | Execute | While/until loops capped at 10,000 iterations |

### Validator vs Executor

The validator and executor have distinct security roles. The **validator** performs fast-fail structural checks on the raw AST — things knowable at parse time like disallowed commands, forbidden syntax, and unapproved variable references. The **executor** is the real security boundary for dynamic values — after expanding variables, globs, and command substitutions, it re-validates command names, checks expanded arguments for path traversal, re-checks blocked flags, and validates redirect targets.

This split exists because bash is a dynamic language. Static analysis of the AST cannot predict what strings expansion will produce (variable substitution, command substitution, glob expansion, parameter expansion all happen at runtime). Rather than trying to statically analyze every bash string-construction mechanism, the validator handles structural concerns and the executor enforces value constraints on the actual expanded strings that get passed to processes.

### Why not OS-level sandboxing?

OS-level sandboxing (macOS Seatbelt, Linux Landlock/seccomp) enforces filesystem restrictions at the kernel level. This sounds like a natural fit — make the filesystem read-only and you don't need to worry about dangerous flags. In practice, it doesn't replace rsh's approach:

- **Commands need system paths to run.** Even `ls` requires read access to `/usr/lib` (shared libraries), `/etc` (locale), `/dev` (devices), and the binary itself in `/usr/bin`. A sandbox must allow these paths, which means commands can still read files outside the working directory — exactly the attack surface rsh's argument validation prevents.
- **Sandboxing doesn't restrict command execution.** Tools like `xargs`, `awk` (`system()`), and `sed` (`s///e`) execute arbitrary commands. A read-only sandbox prevents writes but the executed commands can still read sensitive system files from the allowed paths.
- **It doesn't enable a larger allowlist.** The main motivation for sandboxing would be safely adding powerful commands (sed, awk, xargs). But since the sandbox must allow system paths for anything to work, these tools could still read files outside the working directory — the same reason they're excluded today.
- **It adds platform-specific complexity.** Seatbelt (macOS) and Landlock (Linux) have different APIs, kernel version requirements, and failure modes. The sandbox degrades silently on older systems, creating a false sense of security.

rsh's approach — restricting *which commands* can run and *what arguments* they receive — is simpler, portable, and auditable. The allowlist is the security boundary, not the kernel.

### What rsh does NOT protect against

- **Allowlisted commands behaving dangerously.** The allowlist is intentionally read-only, but allowed commands can still read any file reachable from the working directory.
- **Symlink escapes.** A symlink inside the working directory pointing elsewhere can be followed by allowlisted commands. Redirect path traversal checks do catch symlinks, but argument paths are not resolved.
- **Information disclosure via command output.** An allowlisted `cat` can read any file reachable from the working directory (without `..` traversal). Scope the working directory and allowlist appropriately.

## Architecture

```
input string
     │
     ▼
 brush-parser  ──── parses full bash syntax into typed AST
     │
     ▼
  Validator   ──── structural checks: allowlist, blocked flags, forbidden
     │              syntax, variable approval, redirect gating
     │              (rejects with error on stderr)
     ▼
  Executor    ──── expands variables/globs/substitutions, then re-validates
     │              expanded values: path checks, command re-validation,
     │              blocked flag re-checks, redirect target validation
     │              (spawns processes, wires pipes, handles loops/conditionals)
     ▼
 stdout/stderr/exit code
```

The key principle: **structural checks before execution, value checks after expansion.** The validator catches what's statically knowable from the AST. The executor expands dynamic values and enforces security constraints on the actual strings before passing them to processes.

## Development

```bash
cargo build          # build
cargo test           # run all tests
cargo run -- "ls"    # run directly
```

## License

MIT
