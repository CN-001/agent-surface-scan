# Known false positives (documented, not tested)

These are **intentional** trade-offs of the heuristic rules. They are *not* part of
the enforced `clean/` corpus because they are expected to be flagged.

| Phrase | Rule | Why it fires | Why it is acceptable |
|---|---|---|---|
| `sudo apt-get install ...` in install docs | AGX-002 (low) | bare `sudo` pattern | demoted to low severity: the report says "verify", it no longer fails `--fail-on high` |
| "the CLI has **full access** to the repository" in an API doc | AGI-003 (medium) | `full access` pattern | medium severity, review-level signal |
| `curl https://example.com/release.tgz` (download only, no pipe) | — | not flagged | the rule requires piping into a shell |
| a README listing a Slack webhook for community chat | AGE-002 (medium) | webhook endpoint pattern | medium severity, review-level signal |

The severity split (strong patterns = high/critical, generic phrasings = low/medium)
is what keeps the tool usable on real repositories: run `--fail-on high` in CI and
review the medium/low findings by hand.
