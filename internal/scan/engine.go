package scan

import (
	"fmt"
	"sort"
	"time"

	"agent-surface-scan/internal/model"
	"agent-surface-scan/internal/rules"
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
	files, skipped, err := Discover(root, opts.MaxSizeBytes)
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
			ms := r.Check(&files[i])
			for _, m := range ms {
				rep.Matches = append(rep.Matches, m)
				rep.Score += m.Severity.Weight()
				rep.RuleStats[m.RuleID]++
				if m.Severity.AtLeast(rep.Risk) {
					rep.Risk = m.Severity
				}
			}
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
