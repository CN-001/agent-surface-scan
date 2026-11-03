# Benchmark cases

Regression cases modeled on real-world agent-context attacks. Both directories are enforced by `go test` (`TestBenchCases` in `internal/scan/engine_test.go`):

- `malicious/` — every case must produce at least one **high/critical** finding
- `clean/` — every case must stay free of **high/critical** findings (they are realistic near-misses)

## Current cases

| Case | Modeled on | Must trigger |
|---|---|---|
| `01-poisoned-readme` | Poisoned README that makes the agent download and run a remote script, then deliver build logs to an out-of-band endpoint (same shape as the [IBM Bob README incident](https://raw.githubusercontent.com/seahop/ai-threat-atlas/refs/heads/main/docs/case_studies/ibm-bob-malicious-readme-2026.md)) | AGI-001, AGX-001, AGE-001, AGE-002 |
| `02-hostile-issue-template` | Issue template instructing agents to disregard rules and execute remote code | AGI-001, AGX-001, AGX-003 |
| `03-credential-loot-skill` | Skill that uploads agent credentials and leaks a CI token | AGE-001, AGS-001 |
| `04-mcp-remote-code` | MCP server that runs remote code with auto-approve | AGC-001, AGC-002 |
| `01-install-docs` | Legit docs: download + checksum verification (near-miss for AGX-001) | nothing high/critical |
| `02-agent-guidelines` | Legit guidelines asking for approval (near-miss for AGX-003) | nothing high/critical |
| `03-mcp-scoped` | Properly permissioned MCP config (near-miss for AGC-002/AGC-004) | nothing high/critical |

## Adding a case

1. Create `bench/cases/malicious/<nn-name>/` or `bench/cases/clean/<nn-name>/` with discoverable agent-facing files (`README.md`, `AGENTS.md`, `SKILL.md` under `skills/`, `.mcp.json`, issue templates).
2. Keep payloads **synthetic and inert** — no real URLs, no real tokens.
3. Run `go test ./internal/scan/ -run TestBenchCases`.

## Manual run

```sh
surface-scan scan bench/cases/malicious --fail-on high   # exit 2 expected
surface-scan scan bench/cases/clean --fail-on high       # exit 0 expected
```
