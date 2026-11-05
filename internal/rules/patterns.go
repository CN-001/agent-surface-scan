package rules

import (
	"regexp"
	"strings"

	"github.com/CN-001/agent-surface-scan/internal/model"
)

// patternRules are the regexp-driven detectors (one per conceptual attack).
var patternRules = []Rule{
	patternRule(
		"AGI-001", "Explicit prompt-override instructions", model.High, "ASI01",
		"Text that instructs an agent to ignore, discard or override its previous instructions, rules or system prompt.",
		"Remove or neutralize the passage. If the file is user-contributed (issue, comment, docs), strip instruction-bearing text before feeding it to agents, or gate the file behind a human review step.",
		`(?i)\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|earlier|your|system|developer)\s+(instructions?|prompts?|rules?|guidelines?|context|memory)\b`,
		`(?i)\b(ignore|disregard)\s+everything\s+(above|before|in this file)\b`,
	),

	patternRule(
		"AGI-002", "Role & guardrail manipulation", model.High, "ASI01",
		"Text that tries to flip the agent's role (malicious/unrestricted personas) or disable safety guardrails.",
		"Treat persona-switching and guardrail-disabling language as hostile; never accept it from untrusted files. Add the phrasing to your allowlist scanner and quarantine matching inputs.",
		`(?i)(you are now|now you are|pretend to be|act as)\s+(an?\s+)?(evil|malicious|unrestricted|uncensored|rogue|jailbroken|jail-break|dan)\b`,
		`(?i)\b(developer|god|jailbreak|unfiltered|evil)\s*mode\b`,
		`(?i)\b(ignore|bypass|disable|turn off)\s+(all\s+)?(safety|ethics|ethical|guardrails?|content filters?|security policies?|content policy)\b`,
	),

	severityRule(
		"AGI-003", "Over-broad autonomy grants", "ASI03",
		"Instructions that grant an agent unrestricted command execution, full access or administrator privileges.",
		"Scope agent authority explicitly: whitelist commands, paths and tools; replace broad grants with per-task permissions and human approval for sensitive actions.",
		map[model.Severity][]string{
			model.High: {
				`(?i)\b(run|execute|invoke)\s+any\s+(command|tool|script|code)\b`,
				`(?i)\bunrestricted\s+(access|tools?|shell|terminal|permissions?)\b`,
				`(?i)\b(root|administrator|admin)\s+(access|privileges?|rights)\b`,
			},
			model.Medium: {
				`(?i)\b(full|complete|total)\s+(access|control|permission)\b`,
			},
		},
	),

	agx001Rule(),

	severityRule(
		"AGX-002", "Privilege escalation instructions", "ASI07",
		"Instructions to run as administrator/root, loosen execution policy, or otherwise escalate privileges.",
		"Reject escalation language in agent inputs. Agents must run at the least privilege level required by the task; any escalation must go through a human.",
		map[model.Severity][]string{
			model.High: {
				`(?i)\brun\s*as\s*(administrator|admin|root)\b`,
				`(?i)chmod\s+(777|\+x|u\+s)`,
				`(?i)set-executionpolicy\s+(bypass|unrestricted)`,
				`(?i)-executionpolicy\s+bypass`,
				`(?i)\b(uac\s*bypass|bypassuac)\b`,
				`(?i)\b(-enc|encodedcommand)\s+[a-z0-9+/=]{40,}\b`,
				`(?i)\bsudo\s+(bash|sh|zsh|python3?|perl|ruby|node|nc|ncat|nmap|chmod|passwd|rm\s+-rf|curl|wget|dpkg|systemctl|tee)\b`,
			},
			model.Low: {
				`(?i)\bsudo\b`,
			},
		},
	),

	patternRule(
		"AGX-003", "Approval / human-in-the-loop bypass", model.High, "ASI07",
		"Instructions that tell the agent to skip asking the user, bypass approval, or auto-approve actions.",
		"Keep human approval as the default for side-effectful actions. Remove or rewrite language that suppresses confirmation, and enforce approval policy in code, not in prompt text.",
		`(?i)\bnever\s+(ask|request|require|confirm)\w*\s*(for\s+)?(approval|permission|confirmation|consent|the user)?`,
		`(?i)\b(do not|don'?t|without|skip)\s+(ask|asking)\s*(for\s+)?(approval|permission|confirmation|consent|me|the user)?`,
		`(?i)\b(bypass|skip|disable|turn off)\s+(the\s+)?(human|human-in-the-loop|hitl|approval|confirmation|review|consent)\b`,
		`(?i)\bno\s+questions\s+asked\b`,
		`(?i)\balways\s+(auto-?)?(approve|accept|allow)\b`,
		`(?i)\bauto-?approve\s+(everything|all|any)\b`,
	),

	patternRule(
		"AGE-001", "Data exfiltration instructions", model.Critical, "ASI06",
		"Instructions to send secrets, credentials or other sensitive data to external endpoints (webhooks, pastebins, chat bots).",
		"Treat any instruction that pairs secret-like identifiers with an external URL as hostile. Block outbound delivery of credentials by default and log every such attempt.",
		`(?i)\b(send|upload|post|exfiltrate|export|transmit|deliver|submit|leak|dump|copy|transfer)\s+[^\r\n]{0,120}\b(webhooks?|hooks?|pastebin|discord|telegram|slack|interact\.sh|oast|requestbin|webhook\.site|ngrok|collaborator|canarytokens?|beeceptor|pipedream|burp)\b`,
		`(?i)\b(send|upload|post|exfiltrate|export|transmit|deliver|submit|leak|dump|copy|transfer)\b[^\r\n]{0,80}\b(api[_-]?keys?|access[_-]?tokens?|\.env|auth\.json|id_rsa|private keys?|wallets?|mnemonics?)\b[^\r\n.]{0,60}https?://[^\s"')\]]+`,
	),

	patternRule(
		"AGE-002", "Suspicious webhook / out-of-band endpoints", model.Medium, "ASI06",
		"A URL pointing at webhooks or OOB (out-of-band) services commonly used to receive exfiltrated data.",
		"Review the endpoint. Legitimate integrations should use domain-allowlisted, authenticated webhooks; replace free OOB/paste services with internal log capture.",
		`(?i)https?://[^\s"')\]]*(webhook|hooks\.slack\.com|discord\.com/api/webhooks|oast|interact\.sh|canarytokens|requestbin|collaborator|ngrok|webhook\.site|beeceptor|pipedream|burpcollaborator)[^\s"')\]]*`,
	),

	patternRule(
		"AGEV-001", "Hidden markup payloads", model.Medium, "ASI01",
		"Instruction-bearing text hidden in HTML comments or invisible elements, meant to be read by agents but not humans.",
		"Strip HTML comments and invisible elements from any content before it reaches an agent; alert on instruction keywords found inside them.",
		`(?i)<!--[^>]{0,400}(ignore|override|system|instruction|prompt|secret|token|exfil)[^>]{0,400}-->`,
		`(?i)<(span|div|font|p|a)[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)`,
	),

	patternRule(
		"AGEV-002", "Encoded payloads", model.Medium, "ASI01",
		"Base64/hex-encoded commands near execution verbs, a classic obfuscation pattern for injected payloads.",
		"Decode and inspect encoded strings before any execution path; reject encoded commands in agent-facing text unless produced by a trusted pipeline.",
		`(?i)\b(eval|iex|invoke-expression|exec|execute|run)\b[^\r\n]{0,80}(base64|atob|frombase64|hexdecode|decode)`,
		`(?i)\b(base64|atob|frombase64)\b[^\r\n]{0,80}\b(eval|execute|exec|run|iex|invoke-expression|bash|sh)\b`,
		`(?i)(powershell|pwsh)\b[^\r\n]{0,40}\s-(e|enc|encodedcommand)\s+[a-z0-9+/=]{40,}`,
	),

	rawPatternRule(
		"AGS-001", "Hardcoded live secrets", model.Critical, "ASI03",
		"A secret that matches a known provider pattern (OpenAI, GitHub, AWS, Slack, HuggingFace, private key PEM).",
		"Revoke the exposed credential immediately, rotate it, and move it to a secret manager. Add the pattern to pre-commit hooks and CI scanning.",
		`(?i)\bsk-[a-z0-9]{20,}\b`,
		`(?i)\bghp_[a-z0-9]{36,}\b`,
		`(?i)\bgithub_pat_[a-z0-9_]{22,}\b`,
		`(?i)\bglpat-[a-z0-9-]{20,}\b`,
		`(?i)\bAKIA[0-9A-Z]{16}\b`,
		`(?i)\bASIA[0-9A-Z]{16}\b`,
		`(?i)\bAIza[0-9A-Za-z_-]{35}\b`,
		`(?i)\bxox[baprs]-[0-9a-zA-Z-]{10,}\b`,
		`(?i)\bhf_[a-z0-9]{34,}\b`,
		`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----`,
	),

	rawPatternRule(
		"AGS-002", "JWT-like token (often a documentation example)", model.Medium, "ASI03",
		"An eyJ... value that looks like a JWT. Tutorials frequently embed harmless example tokens, so this stays at medium.",
		"Replace documentation examples with placeholder tokens and never commit real signed tokens.",
		`(?i)\beyJ[a-zA-Z0-9_-]{12,}\.[a-zA-Z0-9_-]{12,}\.[a-zA-Z0-9_-]{12,}\b`,
	),
}

// agx001Rule detects remote-execution instructions. Package-manager hits
// require an install verb close to the URL, and URLs pointing at loopback
// addresses are ignored (they are ordinary documentation examples).
func agx001Rule() Rule {
	patterns := []string{
		`(?i)(curl|wget|iwr|invoke-webrequest|invoke-restmethod)\b[^\r\n]{0,140}?\|\s*(sudo\s+)?(ba)?(sh|zsh|bash|python3?|node|pwsh|powershell|cmd)\b`,
		`(?i)\b(pip3?|pipx)\s+install(\s+[^\s"')\]]+){0,4}\s+(https?://[^\s"')\]]+|git\+https?://[^\s"')\]]+|ssh://git@[^\s"')\]]+)`,
		`(?i)\b(npm|pnpm|yarn|bunx?)\s+(install|i|add|dlx|ci)(\s+[^\s"')\]]+){0,3}\s+(https?://[^\s"')\]]+|git\+https?://[^\s"')\]]+|ssh://git@[^\s"')\]]+)`,
		`(?i)\b(npx|bunx)\s+[^\r\n]{0,60}https?://[^\s"')\]]+`,
		`(?i)\b(cargo|gem)\s+install(\s+[^\s"')\]]+){0,3}\s+(https?://[^\s"')\]]+|git\+https?://[^\s"')\]]+|ssh://git@[^\s"')\]]+)`,
		`(?i)\bgo\s+install(\s+[^\s"')\]]+){0,3}\s+(https?://[^\s"')\]]+|git\+https?://[^\s"')\]]+|ssh://git@[^\s"')\]]+)`,
		`(?i)\b(powershell|pwsh)\b[^\r\n]{0,60}(-enc(odedcommand)?\s|iex\s|invoke-expression\s)`,
	}
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		res = append(res, regexp.MustCompile(p))
	}
	urlRe := regexp.MustCompile(`(?i)https?://[^\s"')\]]+`)
	isLoopback := func(u string) bool {
		host := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"))
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		if i := strings.Index(host, ":"); i >= 0 {
			host = host[:i]
		}
		return host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || host == "::1"
	}
	return Rule{
		ID:       "AGX-001",
		Title:    "Remote command execution",
		Severity: model.Critical,
		ASI:      "ASI07",
		Summary:  "Instructions that download content from a URL and execute it, or that run package/CLI tools against remote code.",
		Fix:      "Never pipe downloaded content into a shell. Require pinned, signed artifacts, hash verification, and human approval before executing anything fetched from the network.",
		Check: func(f *model.File) []model.Match {
			var ms []model.Match
			seen := map[int]bool{}
			for _, re := range res {
				for _, h := range regexLineHits(f, re) {
					if seen[h.line] {
						continue
					}
					if u := urlRe.FindString(h.text); u != "" && isLoopback(u) && !strings.Contains(h.text, "|") {
						continue // documentation example against a local server
					}
					seen[h.line] = true
					ms = append(ms, model.Match{
						RuleID: "AGX-001", Title: "Remote command execution", Severity: model.Critical, ASI: "ASI07",
						File: f.Path, Line: h.line, Column: h.col,
						Evidence: h.text,
						Message:  "Instructions that download content from a URL and execute it, or that run package/CLI tools against remote code.",
						Fix:      "Never pipe downloaded content into a shell. Require pinned, signed artifacts, hash verification, and human approval before executing anything fetched from the network.",
					})
				}
			}
			return ms
		},
	}
}
