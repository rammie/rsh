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

rsh is a restricted shell for AI agents — a command execution sandbox written in Rust. It accepts a bash command string, parses it into an AST using `brush-parser`, validates the entire AST against a security policy, then executes only what's permitted. Default allowlist is read-only commands (grep, cat, ls, find, etc.).

## Architecture

The pipeline is: **parse → validate → execute**. All validation happens before any process spawns.

- **`main.rs`** — CLI argument parsing, wires together allowlist → parser → executor
- **`allowlist.rs`** — Manages the command allowlist (built-in defaults, `~/.rsh/allowlist` config file, `RSH_ALLOWLIST` env var, `--allow` CLI flag; last wins). Also defines `APPROVED_VARS` for environment variable validation.
- **`validator.rs`** — Recursive AST security walker. Walks every node in a `brush_parser::ast::Program` and enforces: command allowlist, blocked flags (find -delete, sed -i), variable reference approval, redirect gating, path traversal checks, rejection of function defs/background/process substitution, and sub-command validation (find -exec, xargs).
- **`executor.rs`** — Walks the validated AST, expands words (variables, globs, command substitution), wires pipes between pipeline stages, handles loops/conditionals, spawns processes with sanitized environment. Manages signal handling (SIGINT/SIGTERM) and output truncation.
- **`glob.rs`** — Glob expansion scoped to working directory with path traversal and absolute path guards.

## Test Structure

- `tests/executor_tests.rs` — Integration tests that invoke the `rsh` binary via `Command` and check stdout/stderr/exit codes
- `tests/integration_tests.rs` — More integration tests
- `tests/parser_tests.rs` — Parser-level tests

Tests use `env!("CARGO_BIN_EXE_rsh")` to get the built binary path.

## Key Design Decisions

- Uses `brush-parser` crate for full bash syntax parsing — no hand-rolled parser
- Validator and executor are separate passes: validator returns `Result<Vec<String>, String>`, executor only runs after validation succeeds
- Output behaves like bash (stdout/stderr/exit code), not JSON
- `sed -i` blocked via prefix matching (catches `-i`, `-i.bak`, `-ibak`); `awk` excluded entirely (its `system()` can execute arbitrary commands)
- Loop iterations capped at 10,000
- Environment sanitized by default (only `APPROVED_VARS` forwarded to children)
- Accepts `-c` flag for bash compatibility (`rsh -c "command"`)
- `--prime` flag outputs an LLM-ready description of capabilities
