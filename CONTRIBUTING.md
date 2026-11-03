# Contributing

Thanks for helping make agent-facing context safer. PRs are welcome.

## Getting started

```sh
git clone https://github.com/CN-001/agent-surface-scan.git
cd agent-surface-scan
go test ./...
```

Requirements: Go 1.24+.

## Adding or changing a rule

1. Add the rule in `internal/rules/patterns.go` (regex) or `internal/rules/mcp.go` (structured checks), with:
   - a unique `ID` (`AGX-`, `AGI-`, `AGE-`, `AGEV-`, `AGD-`, `AGS-`, `AGC-` prefixes by category)
   - severity, ASI mapping, a human-readable summary and a concrete fix
2. Add a positive case to `internal/rules/rules_test.go` **and** a negative case (the same text with a suppression marker, plus a near-miss that must not fire).
3. If it produces obvious false positives on everyday text, tighten the pattern or lower the severity — FP rate matters more than recall here.

## Corpus

- `testdata/corpus/malicious` — files that must trigger rules
- `testdata/corpus/benign` — files that must stay clean of high/critical findings

Both are enforced by `internal/scan/engine_test.go`. Keep samples synthetic and inert.

## Style

- `gofmt` only, no external dependencies
- Rule messages: what was detected + a concrete remediation, in English
- README/CHANGELOG updates for user-visible changes

## License

By contributing you agree your work is licensed under MIT.
