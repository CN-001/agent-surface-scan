# Agent hooks

Hook scripts that run `surface-scan` the moment an AI coding agent is about to read or edit a file in your repository, and block (or warn) when the file is flagged **critical/high**.

| Agent | Script | Decision model |
|---|---|---|
| Claude Code | [claude-code-hook.mjs](claude-code-hook.mjs) | `deny` (default) or `warn` via `SURFACE_SCAN_MODE` |
| OpenAI Codex CLI | [codex-hook.ps1](codex-hook.ps1) | `block` (default) or `warn` via `SURFACE_SCAN_MODE` |

Behavior:

- Only fires for `Read` / `Edit` / `Write` tool calls that carry a file path.
- Runs `surface-scan <cwd> --format json` and filters findings for the target file.
- Blocks only on `critical`/`high`; always **fail-open** when the scanner binary is missing (the hook warns instead of breaking your agent).
- Suppressed findings (inline `surface-scan:ignore` markers or `.surface-scanignore`) are respected automatically.

## Install

1. Build/install the scanner once:

```sh
go install github.com/CN-001/agent-surface-scan/cmd/surface-scan@v0.1.1
```

2. Claude Code — add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Edit|Write",
        "hooks": [{ "type": "command", "command": "node E:\\agent-surface-scan\\hooks\\claude-code-hook.mjs" }]
      }
    ]
  }
}
```

3. Codex CLI — add to `~/.codex/config.toml`:

```toml
[hooks]
PreToolUse = [
  { matcher = "Read|Edit", hooks = [{ type = "command", command = "powershell -NoProfile -ExecutionPolicy Bypass -File E:\\agent-surface-scan\\hooks\\codex-hook.ps1" }] }, # surface-scan:ignore
]
```

## Smoke test

```sh
echo '{"cwd":"E:/agent-surface-scan","tool_name":"Read","tool_input":{"file_path":"bench/cases/malicious/01-poisoned-readme/README.md"}}' | node hooks/claude-code-hook.mjs
```

Expect a `permissionDecision: "deny"` with the findings listed. Point the same payload at a clean file (`bench/cases/clean/01-install-docs/README.md`) and expect `allow`.
