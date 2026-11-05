# Codex PreToolUse hook: block Read/Edit on files agent-surface-scan flags as
# critical/high. Fail-open when the scanner binary is missing.
#
# Install in ~/.codex/config.toml:
#
#   [hooks]
#   PreToolUse = [
#     { matcher = "Read|Edit", hooks = [{ type = "command", command = "powershell -NoProfile -ExecutionPolicy Bypass -File E:\\agent-surface-scan\\hooks\\codex-hook.ps1" }] },
#   ]
#
# Env overrides:
#   SURFACE_SCAN_BIN   path to the surface-scan binary (default: surface-scan on PATH)
#   SURFACE_SCAN_MODE  deny (default) | warn

$ErrorActionPreference = 'SilentlyContinue'

$raw = @($input) -join "`n"
if (-not $raw) { $raw = [Console]::In.ReadToEnd() }
$raw = $raw.TrimStart([char]0xFEFF)
if (-not $raw) { '{"decision":"approve"}'; exit 0 }

try { $hook = $raw | ConvertFrom-Json } catch { '{"decision":"approve"}'; exit 0 }

$toolName = [string]$hook.tool_name
if ($toolName -notin @('Read', 'Edit', 'MultiEdit', 'Write')) { '{"decision":"approve"}'; exit 0 }

$cwd = [string]$hook.cwd
if (-not $cwd) { $cwd = (Get-Location).Path }
$filePath = [string]$hook.tool_input.file_path
if (-not $filePath) { '{"decision":"approve"}'; exit 0 }

$bin = $env:SURFACE_SCAN_BIN
if (-not $bin) { $bin = 'surface-scan.exe' }

$probe = & $bin version 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Error "[agent-surface-scan] scanner binary not found; hook allows (fail-open). Install: go install github.com/CN-001/agent-surface-scan/cmd/surface-scan@v0.2.2"
  '{"decision":"approve"}'
  exit 0
}

# Scan the whole working directory and filter to the target file. The full
# repository scan keeps path-context classification (docs/, skills/) and the
# repository allowlist (.surface-scanignore).
$report = $null
$json = & $bin scan $cwd --format json --fail-on critical 2>$null | Out-String
try { $report = $json | ConvertFrom-Json } catch { '{"decision":"approve"}'; exit 0 }

$target = $filePath.Replace('/', '\').ToLowerInvariant()
$base = $cwd.TrimEnd('\').ToLowerInvariant()
if ($target.StartsWith($base + '\')) {
  $target = $target.Substring($base.Length + 1).Replace('\', '/')
} else {
  $target = $filePath.Replace('\', '/').ToLowerInvariant()
}
$baseName = ([System.IO.Path]::GetFileName($filePath)).ToLowerInvariant()
$findings = @($report.findings | Where-Object {
  $f = [string]$_.file.ToLowerInvariant()
  ($target -eq $f) -or ($target.EndsWith('/' + $f)) -or ($f.EndsWith('/' + $target)) -or ($baseName -eq $f)
})
$serious = @($findings | Where-Object { $_.severity -in @('critical','high') })
if ($serious.Count -eq 0) { '{"decision":"approve"}'; exit 0 }

$lines = ($serious | Select-Object -First 5 | ForEach-Object { "  $($_.severity.ToUpper()) $($_.ruleId): $($_.message)" }) -join "`n"
$reason = "agent-surface-scan flagged $($serious.Count) critical/high issue(s) in this file:`n$lines`nReview before the agent reads it (surface-scan:ignore markers or .surface-scanignore for reviewed exceptions)."

if ($env:SURFACE_SCAN_MODE -eq 'warn') {
  Write-Error "[agent-surface-scan] $reason"
  '{"decision":"approve"}'
  exit 0
}

$reasonEscaped = $reason.Replace('\', '\\').Replace('"', '\"').Replace("`n", '\n')
'{"decision":"block","reason":"' + $reasonEscaped + '"}'
exit 0
