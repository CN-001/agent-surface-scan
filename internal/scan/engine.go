package scan

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/CN-001/agent-surface-scan/internal/model"
	"github.com/CN-001/agent-surface-scan/internal/rules"
)

// Report is the aggregated result of one scan.
type Report struct {
	Root      string
	ScannedAt time.Time
	Files     int
	FileKinds map[model.FileKind]int
	Skipped   []string
	Matches   []model.Match
	Ignored   int // matches suppressed by markers or the allowlist
	Score     int
	Risk      model.Severity
	RuleStats map[string]int
}

// Run discovers agent-facing files under root and executes every rule.
func Run(root string, opts Options) (*Report, error) {
	files, skipped, err := Discover(root, opts)
	if err != nil {
		return nil, err
	}
	rep := &Report{
		Root:      root,
		ScannedAt: time.Now(),
		Files:     len(files),
		FileKinds: map[model.FileKind]int{},
		Skipped:   skipped,
		Risk:      model.Info,
		RuleStats: map[string]int{},
	}
	for _, f := range files {
		rep.FileKinds[f.Kind]++
	}
	rs := rules.All()
	for _, r := range rs {
		for i := range files {
			rep.Matches = append(rep.Matches, r.Check(&files[i])...)
		}
	}
	rep.Matches, rep.Ignored = applyIgnores(files, loadAllowlist(root, opts.AllowlistPath), rep.Matches)

	for _, m := range rep.Matches {
		rep.Score += m.Severity.Weight()
		rep.RuleStats[m.RuleID]++
		if m.Severity.AtLeast(rep.Risk) {
			rep.Risk = m.Severity
		}
	}
	sort.SliceStable(rep.Matches, func(i, j int) bool {
		a, b := rep.Matches[i], rep.Matches[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
	return rep, nil
}

// fileIgnores records inline suppression markers for one file.
type fileIgnores struct {
	all   bool
	lines map[int]bool
}

// allowlistRule matches a glob/prefix pattern to a rule id ("*" = any rule).
type allowlistRule struct {
	pattern string
	rule    string
}

// loadAllowlist reads a .surface-scanignore file (empty result when absent).
//
// Format: one rule per line, `#` starts a comment.
//
//	<pattern> [<ruleID>|*]
//
// Example:
//
//	testdata *
//	docs/legacy AGI-003
func loadAllowlist(root, file string) []allowlistRule {
	if file == "" {
		return nil
	}
	if !path.IsAbs(file) {
		file = path.Join(root, file)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var out []allowlistRule
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		rule := "*"
		if len(fields) >= 2 {
			rule = fields[1]
		}
		out = append(out, allowlistRule{pattern: fields[0], rule: rule})
	}
	return out
}

// applyIgnores drops matches suppressed by inline markers or the allowlist.
//
//	# surface-scan:ignore            ignores findings on this line
//	# surface-scan:ignore-file       ignores all findings in this file
func applyIgnores(files []model.File, allow []allowlistRule, ms []model.Match) ([]model.Match, int) {
	byPath := map[string]*model.File{}
	for i := range files {
		byPath[files[i].Path] = &files[i]
	}
	cache := map[string]fileIgnores{}
	ignoreFor := func(p string) fileIgnores {
		if v, ok := cache[p]; ok {
			return v
		}
		var v fileIgnores
		if f := byPath[p]; f != nil {
			v.lines = map[int]bool{}
			if strings.Contains(strings.ToLower(f.Raw), "surface-scan:ignore-file") {
				v.all = true
			}
			for i, ln := range f.Lines {
				if strings.Contains(strings.ToLower(ln), "surface-scan:ignore") {
					v.lines[i+1] = true
				}
			}
		}
		cache[p] = v
		return v
	}
	allowed := func(p, rule string) bool {
		for _, a := range allow {
			if a.rule != "*" && a.rule != rule {
				continue
			}
			if a.pattern == p || strings.HasPrefix(p, strings.TrimSuffix(a.pattern, "/")+"/") {
				return true
			}
			if ok, err := path.Match(a.pattern, p); err == nil && ok {
				return true
			}
		}
		return false
	}
	out := ms[:0]
	ignored := 0
	for _, m := range ms {
		if v := ignoreFor(m.File); v.all || v.lines[m.Line] {
			ignored++
			continue
		}
		if allowed(m.File, m.RuleID) {
			ignored++
			continue
		}
		out = append(out, m)
	}
	return out, ignored
}

// TopRisk returns the highest severity present, or "none" when there are no findings.
func (r *Report) TopRisk() string {
	if len(r.Matches) == 0 {
		return "none"
	}
	return string(r.Risk)
}

// Summary builds a one-line human summary.
func (r *Report) Summary() string {
	return fmt.Sprintf("%d agent-facing files scanned, %d findings, %d ignored, score=%d, risk=%s",
		r.Files, len(r.Matches), r.Ignored, r.Score, r.TopRisk())
}
