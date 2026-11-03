# agent-surface-scan

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/CN-001/agent-surface-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/CN-001/agent-surface-scan/actions/workflows/ci.yml)

**Scan the AI-agent attack surface of a repository.** A single-binary, dependency-free static scanner that finds prompt-injection vectors, remote-execution instructions, exfiltration prompts, approval-bypass language, hidden characters, deceptive links, hardcoded live secrets and dangerous MCP configurations — in the files coding agents actually read: `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `README`, issue templates, skills, MCP configs and docs.

> 中文简介：一个零依赖单二进制扫描器，专门检查「AI 编码代理会读到的仓库文本」里的提示注入、远程执行、数据外泄、绕过审批、隐藏字符、欺骗性链接、硬编码密钥与危险 MCP 配置。输出文本 / Markdown / JSON / SARIF，可做 CI 门禁，17 条规则全部映射 OWASP Agentic Security Initiative（ASI）分类。

## Why

Coding agents trust repository text as instructions. Attackers have moved from attacking the code to attacking the context: poisoned READMEs that make the agent run remote code and bypass human approval. `agent-surface-scan` is a CI gate for that context — static, fast, and opinionated about what agent-facing text must never do.

## Features

- **17 rules** mapped to the OWASP Agentic Security Initiative (ASI) taxonomy
- Discovers 6 classes of agent-facing files (instructions, README, contributing/security docs, issue/PR templates, skills, MCP configs, docs)
- Four output formats: **text, Markdown, JSON, SARIF 2.1.0** (upload straight to GitHub Code Scanning)
- `--fail-on` CI gate with exit codes; `--exclude` path patterns; `.surface-scanignore` allowlist
- Inline suppression markers (`surface-scan:ignore`, `surface-scan:ignore-file`)
- **[Claude Code](hooks/claude-code-hook.mjs) and [Codex](hooks/codex-hook.ps1) hooks** — block the agent from reading flagged files
- **[DSH plugin](dsh/)** (`agentscan-dsh`) — the `surface_scan` tool + `agentscan` skill inside DeepSeek Harness
- **[Benchmark cases](bench/)** modeled on real-world incidents, enforced in CI
- Pure Go standard library — no runtime dependencies; builds to one binary

## Install

```sh
go install github.com/CN-001/agent-surface-scan/cmd/surface-scan@v0.1.1
```

or build from source:

```sh
git clone https://github.com/CN-001/agent-surface-scan.git
cd agent-surface-scan
go build -o surface-scan ./cmd/surface-scan
```

## Usage

```sh
# scan the current repository (exit code 2 when anything >= high is found)
surface-scan scan .

# SARIF for GitHub Code Scanning
surface-scan scan . --format sarif --out results.sarif --fail-on high

# see which files are treated as agent-facing context
surface-scan scan . --list

# exclude fixtures and vendored docs
surface-scan scan . --exclude testdata,examples

# allowlist: .surface-scanignore lines are "<pattern> <ruleID|*>"
#   testdata *
#   docs/legacy AGI-003
surface-scan scan . --allowlist .surface-scanignore

# generate a GitHub Actions workflow for this repo
surface-scan init-ci

# list all rules
surface-scan rules
```

### Suppression

Two markers, both written as ordinary comments:

| Marker | Effect |
|---|---|
| `# surface-scan:ignore` | suppresses findings on that line (any comment style: `#`, `//`, `<!-- -->`) |
| `# surface-scan:ignore-file` | suppresses all findings in the file |

Use them for intentional, reviewed exceptions (for example a documented example command in your own README) — and require a comment explaining why.

Example of a real report (the flagged line is suppressed in this documentation on purpose):

```text
README.md
  L6    [CRITICAL] AGX-001  Remote command execution (ASI07)
        Instructions that download content from a URL and execute it...
```

## Rules

| ID | Severity | ASI | Description |
|---|---|---|---|
| AGI-001 | high | ASI01 | Explicit "ignore previous instructions" phrasing |
| AGI-002 | high | ASI01 | Role flips and guardrail-disabling language |
| AGI-003 | high | ASI03 | Over-broad autonomy grants (any-command grants, unbounded authority) |
| AGX-001 | critical | ASI07 | Remote code execution (download then pipe to a shell, package install from URL) |
| AGX-002 | high | ASI07 | Privilege escalation phrasing (admin elevation, permissive bits, policy bypass) |
| AGX-003 | high | ASI07 | Approval / human-in-the-loop bypass |
| AGE-001 | critical | ASI06 | Data exfiltration instructions (secrets to external endpoints) |
| AGE-002 | medium | ASI06 | Suspicious webhook / out-of-band endpoints |
| AGEV-001 | medium | ASI01 | Instruction text hidden in HTML comments / invisible elements |
| AGEV-002 | medium | ASI01 | Encoded payloads next to execution verbs |
| AGEV-003 | medium | ASI01 | Invisible zero-width characters |
| AGD-001 | medium | ASI01 | Deceptive links, URL shorteners, homoglyph domains |
| AGS-001 | critical | ASI03 | Hardcoded live secrets (provider token formats, JWTs, private keys) |
| AGC-001 | high | ASI05 | MCP server executing remote code |
| AGC-002 | high | ASI03 | MCP autoApprove / alwaysAllow without scoping |
| AGC-003 | low | ASI05 | Unparseable MCP config |
| AGC-004 | low | ASI03 | MCP server with no permission scoping |

## Integrations

| Integration | Where | What it does |
|---|---|---|
| GitHub Actions / Code Scanning | `surface-scan init-ci` | CI gate + SARIF upload |
| Claude Code | [hooks/claude-code-hook.mjs](hooks/claude-code-hook.mjs) | denies `Read`/`Edit`/`Write` on flagged files |
| OpenAI Codex CLI | [hooks/codex-hook.ps1](hooks/codex-hook.ps1) | blocks `Read`/`Edit` on flagged files |
| DeepSeek Harness | [dsh/](dsh) | `surface_scan` tool + `agentscan` skill |

## Layout

```
cmd/surface-scan      CLI entry point
internal/model        shared types
internal/rules        rule engine (17 rules, OWASP ASI mapping)
internal/scan         file discovery, engine, report rendering
testdata/corpus       malicious / benign regression corpus
testdata/repo         end-to-end demo repository
bench/cases           real-world-inspired benchmark cases
hooks/                Claude Code + Codex hook scripts
dsh/                  DeepSeek Harness plugin (agentscan-dsh)
```

## Development

```sh
go test ./...
go vet ./...
gofmt -l .
```

## Roadmap

- [x] DSH plugin (`agentscan-dsh`): `surface_scan` tool + skill inside DeepSeek Harness
- [x] Codex / Claude Code hooks: warn before an agent reads a dangerous file
- [x] Benchmark cases modeled on real-world poisoned-context incidents
- [ ] Coverage benchmark against a larger public corpus + false-positive report on big repos
- [ ] `--allowlist` review workflow UI (record who reviewed what)

## Security & scope

This tool is **defensive**: it audits your own repositories and is intended for use inside CI and on authorized code only. The bundled corpus contains only synthetic, minimal samples for detection tests — not weaponized payloads. See [SECURITY.md](SECURITY.md).

## Author

Created and maintained by **Aurox** — GitHub [@CN-001](https://github.com/CN-001).

## License

[MIT](LICENSE)
