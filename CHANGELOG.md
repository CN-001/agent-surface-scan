# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-03

### Fixed

- CRLF files: line endings are normalized before matching, so line numbers for multi-line rules (e.g. private-key PEM blocks) no longer drift on Windows checkouts.
- Missing/invalid `scan` root now returns a real error instead of an empty report with exit code 0.
- `--allowlist <absolute path>` was ignored on Windows because the path test used `path` instead of `filepath`.
- `--exclude` and `.surface-scanignore` patterns now accept backslashes (`docs\legacy` works like `docs/legacy`).
- `AGC-002` no longer stops at `autoApprove`: an `alwaysAllow` list on the same server is reported too.
- Repository line endings pinned with `.gitattributes` (LF for source/docs, CRLF for PowerShell scripts).

### Added

- CLI argument parser extracted and covered by tests (`cmd/surface-scan/main_test.go`); `scan` accepts flags before or after the path.
- Regression tests for CRLF line numbers, absolute allowlist paths, backslash excludes and missing roots.

## [0.1.0] - 2026-11-03

### Added

- Initial release: scan the AI-agent attack surface of a repository.
- 17 detection rules mapped to the OWASP Agentic Security Initiative (ASI) taxonomy.
- Discovery of agent-facing files: `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, `COPILOT.md`, README, CONTRIBUTING, SECURITY, issue/PR templates, skills (`SKILL.md`), MCP configs (`.mcp.json`, `.cursor/mcp.json`, `mcp.json`) and `docs/**`.
- Output formats: text, Markdown, JSON, SARIF 2.1.0.
- `--fail-on` CI gate with exit codes, `--max-size`, `--exclude`, `--list`, `--allowlist`.
- Inline suppression markers: `surface-scan:ignore`, `surface-scan:ignore-file`; allowlist file `.surface-scanignore`.
- `init-ci` command generating a GitHub Actions workflow.
- Claude Code and Codex CLI PreToolUse hooks that block reads of flagged files.
- DeepSeek Harness plugin (`agentscan-dsh`) exposing the `surface_scan` tool and `agentscan` skill.
- Malicious/benign regression corpus, real-world-inspired benchmark cases, and unit tests.
- CI workflow: gofmt, vet, test, build, dogfood scan.
