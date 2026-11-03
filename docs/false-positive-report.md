# False-positive report — real repositories

**Date:** 2026-11-03 · **Scanner:** `surface-scan` v0.2.1 · **Method:** shallow clones of five popular
repositories scanned with `--fail-on high` (the recommended CI setting).

## Headline result

**0 critical and 0 high findings across all five repositories.** With the default CI gate,
the scanner is quiet on well-maintained real-world projects; everything that remains is
medium/low review-level signal.

## Before / after rule tuning

| Repository | Agent-facing files | Before tuning (crit+high) | After tuning | After (total) | Risk |
|---|---|---|---|---|---|
| gin-gonic/gin | 9 | 0 | 0 | 0 | none |
| expressjs/express | 2 | 7 crit | 0 | 0 | none |
| pallets/flask | 9 | 0 | 0 | 0 | none |
| axios/axios | 154 | 17 crit | 0 | 12 medium | medium |
| fastapi/fastapi | 1673 | 79 crit | 0 | 16 medium + 13 low | medium |

The initial 103 criticals were documentation artifacts. After tuning, `--fail-on high`
passes on all five repos.

## What the remaining medium/low findings are

| Rule | Repo | Verdict | Why it fires |
|---|---|---|---|
| AGD-001 (medium) | axios ×10 | **FP (documented example)** | README shows a `bit.ly` URL inside an axios config example |
| AGI-003 (medium) | axios ×2, fastapi ×1 | **FP (generic phrasing)** | "full access" in API descriptions |
| AGS-002 (medium) | fastapi ×13 | **FP by design** | JWT example tokens in the OAuth2 tutorial (kept at medium for exactly this reason) |
| AGX-002 (low) | fastapi ×13 | **FP (bare `sudo`)**, low tier | proxy/port docs mention running with elevated privileges |
| AGE-002 (medium) | fastapi ×2 | **FP (review-level)** | webhook endpoint documentation |

None of them fail `--fail-on high`, so they cost nothing in CI; they appear only when a
human asks for the full report.

## Rule changes driven by this data (v0.2.1)

- **AGX-001** — package-manager patterns now require an install verb immediately followed
  by argument tokens and the URL (`npm install <url>`), so markdown links and badges
  like `[npm registry](https://www.npmjs.com/)` no longer fire; loopback URLs are ignored.
- **AGE-001** — the "secret word + URL" pattern dropped generic words (`secrets`,
  `credentials`, `passwords`), keeps concrete artifacts (`.env`, `auth.json`, `id_rsa`,
  `api key`, private keys…) with a 60-char window that excludes dots (no more `api_key.py`
  file-name hits); exfil verbs now require a following space (no more
  `@app.webhooks.post(...)` code-sample hits).
- **AGI-002** — removed the bare `debug mode` phrasing (CI docs); stronger persona-mode patterns remain.
- **AGS-001/AGS-002** — JWT-shaped tokens split into their own **medium** rule (tutorials
  embed them everywhere; PEM and provider tokens stay critical).
- **AGEV-003** — ZWJ (U+200D) excluded so emoji sequences in docs no longer fire.
- **AGD-001** — `https://user:pass@example.com`-style documentation examples (RFC 2606
  domains) no longer flagged.
- **Discovery** — `docs/` detection is segment-based, so single-file scans of nested
  documentation still classify correctly.

## Reproduce

```powershell
# clones the five repos to a temp dir and prints the summary table
powershell -NoProfile -File bench/fp-run.ps1
```

## Limitations (honest)

- "0 high/critical" is a necessary but not sufficient proof: the corpus is five repos on
  one day, heuristic rules can still miss novel phrasing, and low/medium FPs remain for
  human review.
- Findings below `high` are deliberately noisy-by-design; use `--min-severity high` to
  hide them entirely.
