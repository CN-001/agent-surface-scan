// Package rules implements the detection rules of agent-surface-scan.
package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/CN-001/agent-surface-scan/internal/model"
)

// Rule is one detector run against every discovered agent-facing file.
type Rule struct {
	ID       string
	Title    string
	Severity model.Severity
	ASI      string // OWASP Agentic Security Initiative category (ASI01..ASI10)
	Summary  string
	Fix      string
	Check    func(f *model.File) []model.Match
}

// All returns the complete rule set in canonical order.
func All() []Rule {
	rules := append([]Rule{}, patternRules...)
	rules = append(rules, mcpRules...)
	rules = append(rules, linkRule, hiddenTextRule)
	return rules
}

// lineHit locates a regexp hit inside a file.
type lineHit struct {
	line int
	col  int
	text string
}

// snippet shortens a line for evidence display.
func snippet(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

// regexLineHits finds every match of re against each line of f.
func regexLineHits(f *model.File, re *regexp.Regexp) []lineHit {
	var out []lineHit
	for i, ln := range f.Lines {
		for _, m := range re.FindAllStringIndex(ln, -1) {
			out = append(out, lineHit{line: i + 1, col: m[0] + 1, text: snippet(ln)})
		}
	}
	return out
}

// rawHits finds every match of re in the raw content, mapping offsets to lines.
func rawHits(f *model.File, re *regexp.Regexp) []lineHit {
	starts := make([]int, 0, len(f.Lines)+1)
	starts = append(starts, 0)
	pos := 0
	for _, ln := range f.Lines {
		pos += len(ln) + 1 // +1 for the '\n'
		starts = append(starts, pos)
	}
	var out []lineHit
	for _, m := range re.FindAllStringIndex(f.Raw, -1) {
		line := sort.SearchInts(starts, m[0]+1) - 1
		if line < 0 {
			line = 0
		}
		col := m[0] - starts[line] + 1
		ev := ""
		if line < len(f.Lines) {
			ev = snippet(f.Lines[line])
		}
		out = append(out, lineHit{line: line + 1, col: col, text: ev})
	}
	return out
}

// patternRule builds a regexp-driven rule. Hits are deduplicated per line.
func patternRule(id, title string, sev model.Severity, asi, summary, fix string, patterns ...string) Rule {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		res = append(res, regexp.MustCompile(p))
	}
	return Rule{
		ID:       id,
		Title:    title,
		Severity: sev,
		ASI:      asi,
		Summary:  summary,
		Fix:      fix,
		Check: func(f *model.File) []model.Match {
			var ms []model.Match
			seen := map[int]bool{}
			for _, re := range res {
				for _, h := range regexLineHits(f, re) {
					if seen[h.line] {
						continue
					}
					seen[h.line] = true
					ms = append(ms, model.Match{
						RuleID: id, Title: title, Severity: sev, ASI: asi,
						File: f.Path, Line: h.line, Column: h.col,
						Evidence: h.text, Message: summary, Fix: fix,
					})
				}
			}
			return ms
		},
	}
}

// rawPatternRule is like patternRule but matches across line boundaries.
func rawPatternRule(id, title string, sev model.Severity, asi, summary, fix string, patterns ...string) Rule {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		res = append(res, regexp.MustCompile(p))
	}
	return Rule{
		ID:       id,
		Title:    title,
		Severity: sev,
		ASI:      asi,
		Summary:  summary,
		Fix:      fix,
		Check: func(f *model.File) []model.Match {
			var ms []model.Match
			seen := map[int]bool{}
			for _, re := range res {
				for _, h := range rawHits(f, re) {
					if seen[h.line] {
						continue
					}
					seen[h.line] = true
					ms = append(ms, model.Match{
						RuleID: id, Title: title, Severity: sev, ASI: asi,
						File: f.Path, Line: h.line, Column: h.col,
						Evidence: h.text, Message: summary, Fix: fix,
					})
				}
			}
			return ms
		},
	}
}

// severityRule builds a rule whose patterns carry per-tier severities.
// When several patterns hit the same line, the strongest severity wins.
func severityRule(id, title, asi, summary, fix string, tiers map[model.Severity][]string) Rule {
	type tier struct {
		sev model.Severity
		res []*regexp.Regexp
	}
	order := []model.Severity{model.Critical, model.High, model.Medium, model.Low, model.Info}
	var compiled []tier
	for _, sev := range order {
		pats := tiers[sev]
		if len(pats) == 0 {
			continue
		}
		res := make([]*regexp.Regexp, 0, len(pats))
		for _, p := range pats {
			res = append(res, regexp.MustCompile(p))
		}
		compiled = append(compiled, tier{sev: sev, res: res})
	}
	return Rule{
		ID:       id,
		Title:    title,
		Severity: compiled[0].sev,
		ASI:      asi,
		Summary:  summary,
		Fix:      fix,
		Check: func(f *model.File) []model.Match {
			type best struct {
				sev model.Severity
				h   lineHit
			}
			pick := map[int]best{}
			for _, t := range compiled {
				for _, re := range t.res {
					for _, h := range regexLineHits(f, re) {
						if cur, ok := pick[h.line]; !ok || t.sev.AtLeast(cur.sev) {
							pick[h.line] = best{sev: t.sev, h: h}
						}
					}
				}
			}
			lines := make([]int, 0, len(pick))
			for l := range pick {
				lines = append(lines, l)
			}
			sort.Ints(lines)
			var ms []model.Match
			for _, l := range lines {
				b := pick[l]
				ms = append(ms, model.Match{
					RuleID: id, Title: title, Severity: b.sev, ASI: asi,
					File: f.Path, Line: b.h.line, Column: b.h.col,
					Evidence: b.h.text, Message: summary, Fix: fix,
				})
			}
			return ms
		},
	}
}
