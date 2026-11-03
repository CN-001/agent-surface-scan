package scan

import (
	"fmt"
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
	rep.Matches = applyIgnores(files, rep.Matches)

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

// applyIgnores drops matches suppressed by surface-scan:ignore markers.
//
//	# surface-scan:ignore            ignores findings on this line
//	# surface-scan:ignore-file       ignores all findings in this file
func applyIgnores(files []model.File, ms []model.Match) []model.Match {
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
	out := ms[:0]
	for _, m := range ms {
		if v := ignoreFor(m.File); v.all || v.lines[m.Line] {
			continue
		}
		out = append(out, m)
	}
	return out
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
	return fmt.Sprintf("%d agent-facing files scanned, %d findings, score=%d, risk=%s",
		r.Files, len(r.Matches), r.Score, r.TopRisk())
}
