#!/usr/bin/env node
// Claude Code PreToolUse hook: deny Read/Edit/Write on files that
// agent-surface-scan flags as critical/high. Fail-open by design:
// if the scanner binary is unavailable, the hook allows and warns.
//
// Install in ~/.claude/settings.json:
// {
//   "hooks": {
//     "PreToolUse": [
//       {
//         "matcher": "Read|Edit|Write",
//         "hooks": [{ "type": "command", "command": "node <this file>" }]
//       }
//     ]
//   }
// }
//
// Env overrides:
//   SURFACE_SCAN_BIN   path to the surface-scan binary (default: surface-scan on PATH)
//   SURFACE_SCAN_MODE  deny (default) | warn   (warn never blocks)

import { spawnSync } from "node:child_process";
import { basename, relative } from "node:path";

let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;

const deny = (reason) => {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
};

const allow = () => {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
    },
  }));
  process.exit(0);
};

let hook;
try {
  hook = JSON.parse(input.replace(/^\uFEFF/, "").trim() || "{}");
} catch {
  allow();
}

const mode = process.env.SURFACE_SCAN_MODE || "deny";
const toolName = hook.tool_name || "";
if (!["Read", "Edit", "Write", "MultiEdit", "NotebookEdit"].includes(toolName)) allow();

const cwd = hook.cwd || process.cwd();
const filePath = hook.tool_input?.file_path || hook.tool_input?.notebook_path || "";
if (!filePath) allow();

const bin =
  process.env.SURFACE_SCAN_BIN ||
  (process.platform === "win32" ? "surface-scan.exe" : "surface-scan");

const probe = spawnSync(bin, ["version"], { timeout: 5000 });
if (probe.error || probe.status !== 0) {
  process.stderr.write("[agent-surface-scan] scanner binary not found; hook allows (fail-open). Install with: go install github.com/CN-001/agent-surface-scan/cmd/surface-scan@v0.2.1\n");
  allow();
}

// Scan the whole working directory and filter to the target file. The full
// repository scan keeps path-context classification (docs/, skills/) and the
// repository allowlist (.surface-scanignore).
const res = spawnSync(bin, ["scan", cwd, "--format", "json", "--fail-on", "critical"], {
  timeout: 20000,
  maxBuffer: 16 * 1024 * 1024,
});

let report = null;
try {
  report = JSON.parse((res.stdout || "").toString("utf8"));
} catch {
  // unreadable output: do not block
  allow();
}

const relTarget = relative(cwd, filePath).replaceAll("\\", "/").toLowerCase();
const baseTarget = basename(filePath).toLowerCase();
const findings = (report?.findings || []).filter((f) => {
  const fPath = (f.file || "").toLowerCase();
  return (
    relTarget === fPath ||
    relTarget.endsWith("/" + fPath) ||
    fPath.endsWith("/" + relTarget) ||
    baseTarget === fPath
  );
});

const serious = findings.filter((f) => f.severity === "critical" || f.severity === "high");
if (serious.length === 0) allow();

const lines = serious.slice(0, 5).map((f) => `  ${f.severity.toUpperCase()} ${f.ruleId}: ${f.message}`);
const reason = `agent-surface-scan flagged ${serious.length} critical/high issue(s) in this file:\n${lines.join("\n")}\nReview before the agent reads it (surface-scan:ignore markers or .surface-scanignore for reviewed exceptions).`;

if (mode === "warn") {
  process.stderr.write(`[agent-surface-scan] ${reason}\n`);
  allow();
}
deny(reason);
