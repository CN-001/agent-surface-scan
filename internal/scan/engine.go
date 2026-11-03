package scan

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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
// root may be a directory or a single file.
func Run(root string, opts Options) (*Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("scan root %q: %w", root, err)
	}
	if info.IsDir() {
		files, skipped, err := Discover(root, opts)
		if err != nil {
			return nil, err
		}
		return runCore(root, files, skipped, opts)
	}
	files, err := scanSingleFile(root, opts)
	if err != nil {
		return nil, err
	}
	return runCore(filepath.Dir(root), files, nil, opts)
}

// scanSingleFile loads one file and prepares it for scanning when it is
// agent-facing. Non-agent-facing files produce an empty scan. Classification
// uses the full path so nested conventions (docs/, skills/) still apply.
func scanSingleFile(abs string, opts Options) ([]model.File, error) {
	rel := filepath.ToSlash(filepath.Base(abs))
	kind, ok := classify(filepath.ToSlash(abs), filepath.Base(abs))
	if !ok || excluded(rel, opts.Exclude) {
		return nil, nil
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", abs, err)
	}
	if len(raw) > 0 && raw[0] == 0xEF && len(raw) > 2 && raw[1] == 0xBB && raw[2] == 0xBF {
		raw = raw[3:]
	}
	if looksBinary(raw) || !utf8.Valid(raw) {
		return nil, nil
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	return []model.File{{
		Path:  rel,
		Abs:   abs,
		Kind:  kind,
		Raw:   text,
		Lines: strings.Split(text, "\n"),
	}}, nil
}

// filterRules applies the --rules / --skip-rules selection.
func filterRules(all []rules.Rule, opts Options) []rules.Rule {
	if len(opts.Rules) == 0 && len(opts.SkipRules) == 0 {
		return all
	}
	only := map[string]bool{}
	for _, id := range opts.Rules {
		only[id] = true
	}
	skip := map[string]bool{}
	for _, id := range opts.SkipRules {
		skip[id] = true
	}
	out := all[:0]
	for _, r := range all {
		if len(only) > 0 && !only[r.ID] {
			continue
		}
		if skip[r.ID] {
			continue
		}
		out = append(out, r)
	}
	return out
}

func runCore(root string, files []model.File, skipped []string, opts Options) (*Report, error) {
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
	for _, r := range filterRules(rules.All(), opts) {
		for i := range files {
			rep.Matches = append(rep.Matches, r.Check(&files[i])...)
		}
	}
	rep.Matches, rep.Ignored = applyIgnores(files, loadAllowlist(root, opts.AllowlistPath), rep.Matches)

	if opts.MinSeverity != "" && opts.MinSeverity != "info" {
		if minSev, err := model.ParseSeverity(opts.MinSeverity); err == nil {
			kept := rep.Matches[:0]
			for _, m := range rep.Matches {
				if m.Severity.AtLeast(minSev) {
					kept = append(kept, m)
				}
			}
			rep.Matches = kept
		}
	}

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
	if !filepath.IsAbs(file) {
		file = filepath.Join(root, file)
	}
	raw, err := os.ReadFile(filepath.FromSlash(file))
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
		pattern := strings.ReplaceAll(fields[0], "\\", "/")
		rule := "*"
		if len(fields) >= 2 {
			rule = fields[1]
		}
		out = append(out, allowlistRule{pattern: pattern, rule: rule})
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
