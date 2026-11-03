# Security Policy

## Scope

`agent-surface-scan` is a defensive static-analysis tool for repositories. It never executes the content it scans.

## Reporting a vulnerability

If you find a vulnerability in `agent-surface-scan` itself (a detection bypass, a crash, a DoS via crafted input, a path/parsing issue):

1. Do **not** open a public issue with exploit details.
2. Open a [private security advisory](https://github.com/CN-001/agent-surface-scan/security/advisories/new) with:
   - affected version(s)
   - a minimal reproducer (a crafted repository/file)
   - impact assessment

We aim to acknowledge within 48 hours and publish a fix + advisory.

## Rules of engagement for contributors

- Detection rules must stay **static**: the scanner reads files only and must not follow links or fetch remote content.
- Sample payloads in `testdata/` must be synthetic, inert, and clearly non-weaponized.
- Never submit real credentials or tokens; use fabricated patterns that match the same shapes.
- Changes to detection logic require tests against both the malicious and benign corpora.

## Supported versions

| Version | Supported |
|---|---|
| v0.1.x | ✅ |

## Disclaimer

Findings are heuristics: they flag risk, not proven exploitation. Always review flagged content with a human before taking action. No false-positive-free guarantees.
