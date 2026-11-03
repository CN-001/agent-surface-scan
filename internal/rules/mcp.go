package rules

import (
	"encoding/json"
	"regexp"
	"strings"

	"agent-surface-scan/internal/model"
)

// mcpServer is the subset of an MCP client config entry we care about.
type mcpServer struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	URL         string            `json:"url"`
	AutoApprove json.RawMessage   `json:"autoApprove"` // bool or string
	AlwaysAllow []string          `json:"alwaysAllow"`
	Permissions json.RawMessage   `json:"permissions"`
	Tools       json.RawMessage   `json:"tools"`
	Env         map[string]string `json:"env"`
}

type mcpConfigDoc struct {
	McpServers map[string]json.RawMessage `json:"mcpServers"`
}

var (
	mcpExecRe    = regexp.MustCompile(`(?i)\b(curl|wget|eval|iex|bash|sh|powershell|pwsh|cmd|python3?|node|npx|perl|ruby)\b`)
	mcpPayloadRe = regexp.MustCompile(`(?i)(https?://|base64|webhook|ngrok|oast|interact\.sh|canarytoken|requestbin|collaborator)`)
	mcpSuspURLRe = regexp.MustCompile(`(?i)(webhook|ngrok|oast|interact\.sh|canarytokens|requestbin|collaborator|beeceptor|pipedream|webhook\.site)`)
)

func parseMCP(f *model.File) (*mcpConfigDoc, error) {
	var doc mcpConfigDoc
	if err := json.Unmarshal([]byte(f.Raw), &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func autoApproveTrue(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.EqualFold(strings.TrimSpace(s), "true")
	}
	return false
}

func mcpMatch(f *model.File, ruleID, title string, sev model.Severity, asi, server, summary, fix string, line int) model.Match {
	col := 1
	if line > 0 && line <= len(f.Lines) {
		col = strings.Index(f.Lines[line-1], server) + 1
		if col == 0 {
			col = 1
		}
	}
	ev := snippet(f.Raw)
	if line > 0 && line <= len(f.Lines) {
		ev = snippet(f.Lines[line-1])
	}
	return model.Match{
		RuleID: ruleID, Title: title, Severity: sev, ASI: asi,
		File: f.Path, Line: line, Column: col,
		Evidence: ev, Message: summary, Fix: fix,
	}
}

// findServerLine returns the 1-based line whose text contains the server name.
func findServerLine(f *model.File, name string) int {
	for i, ln := range f.Lines {
		if strings.Contains(ln, name) {
			return i + 1
		}
	}
	return 0
}

var mcpRules = []Rule{
	{
		ID:       "AGC-001",
		Title:    "Dangerous MCP server command",
		Severity: model.High,
		ASI:      "ASI05",
		Summary:  "An MCP server whose launch command mixes execution verbs with remote content (URLs, encoded payloads or webhook endpoints).",
		Fix:      "Only allow servers from trusted, pinned package names. Never launch servers that fetch remote code; pin versions and audit server commands in code review.",
		Check: func(f *model.File) []model.Match {
			if f.Kind != model.KindMCPConfig {
				return nil
			}
			doc, err := parseMCP(f)
			if err != nil {
				return nil // AGC-003 handles unparseable configs
			}
			var ms []model.Match
			for name, raw := range doc.McpServers {
				var s mcpServer
				if json.Unmarshal(raw, &s) != nil {
					continue
				}
				cmd := strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
				if cmd != "" && mcpExecRe.MatchString(cmd) && mcpPayloadRe.MatchString(cmd) {
					ms = append(ms, mcpMatch(f, "AGC-001", "Dangerous MCP server command", model.High, "ASI05", name,
						`MCP server "`+name+`" executes `+cmd+` — execution combined with remote content.`,
						"Replace with a trusted, version-pinned server package; never run remote code as an MCP server.",
						findServerLine(f, name)))
				}
			}
			return ms
		},
	},
	{
		ID:       "AGC-002",
		Title:    "MCP auto-approve / over-permissioned config",
		Severity: model.High,
		ASI:      "ASI03",
		Summary:  "An MCP server is configured to auto-approve its tool calls, or whitelists tools without scoping.",
		Fix:      "Set autoApprove to false and keep an empty or explicit alwaysAllow list. Grant tool permissions per task with the least privilege.",
		Check: func(f *model.File) []model.Match {
			if f.Kind != model.KindMCPConfig {
				return nil
			}
			doc, err := parseMCP(f)
			if err != nil {
				return nil
			}
			var ms []model.Match
			for name, raw := range doc.McpServers {
				var s mcpServer
				if json.Unmarshal(raw, &s) != nil {
					continue
				}
				line := findServerLine(f, name)
				if autoApproveTrue(s.AutoApprove) {
					ms = append(ms, mcpMatch(f, "AGC-002", "MCP auto-approve / over-permissioned config", model.High, "ASI03", name,
						`MCP server "`+name+`" has autoApprove enabled.`,
						"Disable autoApprove; approve tool calls per invocation.",
						line))
					continue
				}
				if len(s.AlwaysAllow) > 0 {
					ms = append(ms, mcpMatch(f, "AGC-002", "MCP auto-approve / over-permissioned config", model.Medium, "ASI03", name,
						`MCP server "`+name+`" always-allows `+strings.Join(s.AlwaysAllow, ", ")+`.`,
						"Shrink the alwaysAllow list to the smallest necessary set.",
						line))
				}
			}
			return ms
		},
	},
	{
		ID:       "AGC-003",
		Title:    "Unparseable MCP config",
		Severity: model.Low,
		ASI:      "ASI05",
		Summary:  "An MCP config file that cannot be parsed as JSON — possibly malformed or obfuscated.",
		Fix:      "Validate MCP configs in CI and reject unparseable files; keep agent tool manifests machine-checkable.",
		Check: func(f *model.File) []model.Match {
			if f.Kind != model.KindMCPConfig {
				return nil
			}
			if _, err := parseMCP(f); err != nil {
				return []model.Match{mcpMatch(f, "AGC-003", "Unparseable MCP config", model.Low, "ASI05", "",
					"MCP config could not be parsed as JSON.", "Validate JSON syntax and schema.", 1)}
			}
			return nil
		},
	},
	{
		ID:       "AGC-004",
		Title:    "MCP server lacks permission scoping",
		Severity: model.Low,
		ASI:      "ASI03",
		Summary:  "An MCP server has no permissions/tools scoping metadata, so its capabilities are unbounded by default.",
		Fix:      "Add explicit permissions (read/write/network/tools) for each server, even if the current default is permissive.",
		Check: func(f *model.File) []model.Match {
			if f.Kind != model.KindMCPConfig {
				return nil
			}
			doc, err := parseMCP(f)
			if err != nil {
				return nil
			}
			var ms []model.Match
			for name, raw := range doc.McpServers {
				var s mcpServer
				if json.Unmarshal(raw, &s) != nil {
					continue
				}
				if len(s.Permissions) == 0 && len(s.Tools) == 0 && (s.Command != "" || s.URL != "") {
					ms = append(ms, mcpMatch(f, "AGC-004", "MCP server lacks permission scoping", model.Low, "ASI03", name,
						`MCP server "`+name+`" declares no permissions/tools scoping.`,
						"Declare explicit tool/permission scopes for the server.",
						findServerLine(f, name)))
				}
			}
			return ms
		},
	},
}

var (
	mdLinkRe    = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	bareURLRe   = regexp.MustCompile(`(?i)https?://[^\s"')\]]+`)
	shortenerRe = regexp.MustCompile(`(?i)https?://(bit\.ly|tinyurl\.com|t\.co|rb\.gy|ouo\.io|is\.gd|cut\.ly|shorturl\.at|cutt\.ly|goo\.gl)/`)
	userinfoRe  = regexp.MustCompile(`(?i)https?://[^/\s"')\]]+@[^/\s"')\]]+`)
	domainRe    = regexp.MustCompile(`(?i)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+`)
)

// confusableRunes are homoglyphs from non-Latin scripts that imitate Latin.
var confusableRunes = map[rune]bool{
	'а': true, 'е': true, 'о': true, 'р': true, 'с': true, 'х': true, 'у': true, 'і': true, 'ј': true, // Cyrillic / other
	'α': true, 'ο': true, 'ρ': true, 'τ': true, 'ι': true, 'κ': true, 'ν': true, 'υ': true, 'ω': true, // Greek
	'ӏ': true, 'ԁ': true, 'һ': true, 'ѕ': true, 'ϲ': true, 'ɡ': true, 'ｇ': true, 'ｅ': true, 'ａ': true, // various
}

func hostOf(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func hasConfusable(s string) bool {
	c := 0
	for _, r := range s {
		if confusableRunes[r] {
			c++
		}
	}
	return c >= 2
}

func matchesDomain(t string) string {
	m := domainRe.FindString(strings.ToLower(t))
	return strings.TrimSuffix(m, ".")
}

// linkRule detects deceptive markdown links, shorteners, userinfo URLs and homoglyph domains.
var linkRule = Rule{
	ID:       "AGD-001",
	Title:    "Deceptive links & homoglyph domains",
	Severity: model.Medium,
	ASI:      "ASI01",
	Summary:  "A link whose visible text points at a different destination than the real URL, a URL shortener hiding its target, or a homoglyph domain imitating a trusted name.",
	Fix:      "Render full URLs, ban shorteners for anything agents may open, and reject domains that mix scripts (register punycode and require xn-- display).",
	Check: func(f *model.File) []model.Match {
		var ms []model.Match
		add := func(line int, col int, ev, msg string) {
			ms = append(ms, model.Match{
				RuleID: "AGD-001", Title: "Deceptive links & homoglyph domains",
				Severity: model.Medium, ASI: "ASI01",
				File: f.Path, Line: line, Column: col, Evidence: snippet(ev), Message: msg,
				Fix: "Use plain full URLs, no shorteners; display punycode for non-Latin domains; verify link text matches target host.",
			})
		}
		seen := map[int]bool{}
		for i, ln := range f.Lines {
			// markdown links: visible text vs target
			for _, m := range mdLinkRe.FindAllStringSubmatch(ln, -1) {
				text, href := m[1], m[2]
				tHost := matchesDomain(text)
				hHost := hostOf(href)
				if tHost != "" && hHost != "" && tHost != hHost {
					if shortenerRe.MatchString(href) || mcpSuspURLRe.MatchString(href) || strings.HasSuffix(strings.ToLower(href), ".exe") {
						add(i+1, 0, ln, "Link text shows "+tHost+" but targets "+hHost+" ("+href+")")
						seen[i] = true
					}
				}
			}
			for _, u := range bareURLRe.FindAllString(ln, -1) {
				if shortenerRe.MatchString(u) && !seen[i] {
					add(i+1, 0, ln, "Shortened URL hides its destination: "+u)
					seen[i] = true
					continue
				}
				if userinfoRe.MatchString(u) && !seen[i] {
					add(i+1, 0, ln, "URL carries userinfo/credentials: "+u)
					seen[i] = true
					continue
				}
				h := hostOf(u)
				if h != "" && !strings.HasPrefix(h, "xn--") && hasConfusable(h) && !seen[i] {
					add(i+1, 0, ln, "Homoglyph domain imitates a Latin name: "+h)
					seen[i] = true
				}
			}
		}
		return ms
	},
}

var zeroWidth = map[rune]bool{
	'\u200b': true, '\u200c': true, '\u200d': true, '\u2060': true,
	'\ufeff': true, '\u00ad': true, '\u034f': true, '\u061c': true,
}

// hiddenTextRule flags lines that smuggle invisible characters.
var hiddenTextRule = Rule{
	ID:       "AGEV-003",
	Title:    "Invisible / zero-width characters",
	Severity: model.Medium,
	ASI:      "ASI01",
	Summary:  "Invisible characters (zero-width spaces, word joiners, BOM, soft hyphens) that can split keywords to evade filters or watermark hidden instructions.",
	Fix:      "Strip or escape invisible characters before content reaches an agent; alert when a line contains several of them.",
	Check: func(f *model.File) []model.Match {
		var ms []model.Match
		for i, ln := range f.Lines {
			c := 0
			for _, r := range ln {
				if zeroWidth[r] {
					c++
				}
			}
			if c >= 3 {
				ms = append(ms, model.Match{
					RuleID: "AGEV-003", Title: "Invisible / zero-width characters",
					Severity: model.Medium, ASI: "ASI01",
					File: f.Path, Line: i + 1, Column: 1,
					Evidence: snippet(ln),
					Message:  "Line contains invisible zero-width characters.",
					Fix:      "Strip invisible characters and inspect the line for smuggled instructions.",
				})
			}
		}
		return ms
	},
}

// ensure a compile-time reference to the model package in this file set is not needed;
// keep zero-width handling local to hiddenTextRule.
