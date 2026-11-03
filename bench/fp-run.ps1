# FP runner — reproduces docs/false-positive-report.md on demand.
# Clones five popular repositories into $env:TEMP and prints the summary table.
param(
  [string]$Scanner = "surface-scan"
)

$ErrorActionPreference = 'Continue'
$root = Join-Path $env:TEMP 'surface-scan-fptest'
New-Item -ItemType Directory -Force "$root\repos" | Out-Null

$targets = @{
  'gin'     = 'https://github.com/gin-gonic/gin.git'
  'express' = 'https://github.com/expressjs/express.git'
  'flask'   = 'https://github.com/pallets/flask.git'
  'axios'   = 'https://github.com/axios/axios.git'
  'fastapi' = 'https://github.com/fastapi/fastapi.git'
}

foreach ($name in $targets.Keys) {
  $dst = Join-Path "$root\repos" $name
  if (-not (Test-Path "$dst\.git")) {
    git clone --depth 1 $targets[$name] $dst 2>$null | Out-Null
    Write-Host "cloned $name"
  }
}

"`n{0,-8} {1,8} {2,8} {3,8} {4,8} {5,8} {6,8}" -f 'repo','files','total','crit','high','med','low'
foreach ($name in $targets.Keys) {
  $json = & $Scanner scan (Join-Path "$root\repos" $name) --format json --fail-on critical 2>$null | Out-String
  $o = $json | ConvertFrom-Json
  "{0,-8} {1,8} {2,8} {3,8} {4,8} {5,8} {6,8}" -f $name, $o.files, $o.findings.Count,
    ($o.findings | Where-Object severity -eq 'critical').Count,
    ($o.findings | Where-Object severity -eq 'high').Count,
    ($o.findings | Where-Object severity -eq 'medium').Count,
    ($o.findings | Where-Object severity -eq 'low').Count
}
