# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build              # build
cargo test               # run all tests
cargo test --test executor_tests                  # run one test file
cargo test --test executor_tests test_simple_echo # run a single test
cargo run -- "ls -la"    # run rsh directly
cargo install --path .   # install locally
```

## What This Is

rsh is a restricted shell for AI agents — a command execution sandbox written in Rust. It accepts a bash command string, parses it into an AST using `brush-parser`, validates the entire AST against a security policy, then executes only what's permitted. The allowlist is pinned at compile time to read-only commands (grep, cat, ls, find, etc.) and cannot be changed at runtime.

## Architecture

The pipeline is: **parse → validate → execute**.
Validation helps to fail early and give better error messages.
Complex attack vectors are handled during execution as `rsh` handles command dispatch.

- **`main.rs`** — CLI argument parsing, wires together allowlist → parser → executor
- **`allowlist.rs`** — Pinned command allowlist (compile-time only, no runtime override). Defines `FORWARDED_VARS` (env vars passed to child processes; not available in command arguments).
- **`validator.rs`** — Recursive AST security walker. Structural checks only: command allowlist, blocked flags (find -delete), variable reference approval, redirect gating, rejection of function defs/background/process substitution, and command substitution validation.
- **`executor.rs`** — Walks the validated AST, expands words (variables, globs, command substitution), wires pipes between pipeline stages, handles loops/conditionals, spawns processes with sanitized environment. **The executor is the security boundary for dynamic values** — it re-validates command names, checks expanded arguments for absolute paths and `..` traversal, re-checks blocked flags, and validates redirect targets, all post-expansion. Manages signal handling (SIGINT/SIGTERM) and output truncation.
- **`sed.rs`** — Built-in restricted sed: only supports `-n` with address + `p` command for line extraction (e.g., `sed -n '10,20p' file`). No real sed binary is executed — this runs entirely in-process, eliminating the risk of sed's `e` (execute), `w` (write), and `s///e` features.
- **`glob.rs`** — Glob expansion scoped to working directory with path traversal and absolute path guards.

## Security Model: Validator vs Executor

The validator and executor have distinct security roles:

- **Validator** — fast-fail structural checks on the raw AST. Catches things knowable at parse time: disallowed commands (checked against the pinned allowlist), forbidden syntax (function defs, `&`, process substitution), blocked flags on literal args, unapproved variable references, and redirect gating. Does NOT check paths in arguments — raw `Word.value` strings contain quotes and unexpanded variables, making static path analysis both incomplete and over-restrictive.
- **Executor** — the real security boundary. After expanding variables, globs, and command substitutions, the executor re-validates everything on the actual strings that will be passed to `execve()`: command names against the allowlist, arguments for absolute paths and `..` traversal, blocked flags on expanded args, and redirect targets. This is where path checking lives because it's the only place that sees final, expanded values.

This split exists because bash is a dynamic language — static analysis of the AST cannot fully predict what strings expansion will produce. Rather than playing whack-a-mole with every bash string-construction mechanism (parameter expansion variants, command substitution, etc.), the validator handles structural concerns and the executor handles value concerns post-expansion.

## Test Structure

- `tests/executor_tests.rs` — Integration tests that invoke the `rsh` binary via `Command` and check stdout/stderr/exit codes
- `tests/integration_tests.rs` — More integration tests
- `tests/parser_tests.rs` — Parser-level tests

Tests use `env!("CARGO_BIN_EXE_rsh")` to get the built binary path.

## Key Design Decisions

- Uses `brush-parser` crate for full bash syntax parsing — no hand-rolled parser
- Validator and executor are separate passes: validator returns `Result<Vec<String>, String>`, executor only runs after validation succeeds
- Output behaves like bash (stdout/stderr/exit code), not JSON
- The command allowlist is pinned at compile time — no `--allow` flag, no config file, no env var override. This eliminates the whack-a-mole problem of blocking dangerous commands: only explicitly listed commands can run
- Loop iterations capped at 10,000
- Environment sanitized by default (only `FORWARDED_VARS` like PATH, LANG forwarded to children; no env vars allowed in arguments)
- Accepts `-c` flag for bash compatibility (`rsh -c "command"`)
- `--prime` flag outputs an LLM-ready description of capabilities
- Symlink traversal is a non-goal: rsh restricts which commands can run and validates argument strings for path traversal, but does not prevent commands from following symlinks to files outside the working directory. The caller is responsible for ensuring the working directory does not contain symlinks to sensitive locations.
- `--inherit-env` exposes all parent environment variables to child processes — including `printenv` and `env`, which are on the allowlist. Callers should be aware that sensitive env vars (tokens, secrets) will be readable. Library-injection vars (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`, `DYLD_FRAMEWORK_PATH`, `DYLD_LIBRARY_PATH`) are always stripped, even in `--inherit-env` mode.
- `--allow-redirects` follows symlinks: if a file in the working directory is a symlink to an external path, `>` and `>>` will write through the symlink. This is consistent with the symlink non-goal above but has higher impact since redirects are write operations.
