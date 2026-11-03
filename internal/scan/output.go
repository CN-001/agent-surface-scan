package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CN-001/agent-surface-scan/internal/model"
	"github.com/CN-001/agent-surface-scan/internal/rules"
)

// RenderText writes a plain-text report.
func RenderText(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "agent-surface-scan report\n")
	fmt.Fprintf(w, "root:      %s\n", rep.Root)
	fmt.Fprintf(w, "scanned:   %s\n", rep.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "files:     %d\n", rep.Files)
	if len(rep.Skipped) > 0 {
		fmt.Fprintf(w, "skipped:   %d (%s)\n", len(rep.Skipped), strings.Join(rep.Skipped[:min(3, len(rep.Skipped))], ", "))
	}
	fmt.Fprintf(w, "findings:  %d\n", len(rep.Matches))
	fmt.Fprintf(w, "score:     %d\n", rep.Score)
	fmt.Fprintf(w, "risk:      %s\n\n", rep.TopRisk())

	if len(rep.Matches) == 0 {
		fmt.Fprintf(w, "No findings. The agent-facing surface looks clean.\n")
		return
	}

	cur := ""
	for _, m := range rep.Matches {
		if m.File != cur {
			cur = m.File
			fmt.Fprintf(w, "\n%s\n", cur)
		}
		fmt.Fprintf(w, "  L%-4d [%s] %s  %s (%s)\n", m.Line, strings.ToUpper(string(m.Severity)), m.RuleID, m.Title, m.ASI)
		fmt.Fprintf(w, "        %s\n", m.Message)
		if m.Evidence != "" {
			fmt.Fprintf(w, "        > %s\n", m.Evidence)
		}
		fmt.Fprintf(w, "        fix: %s\n", m.Fix)
	}

	fmt.Fprintf(w, "\nRule summary:\n")
	for _, r := range rules.All() {
		if n := rep.RuleStats[r.ID]; n > 0 {
			fmt.Fprintf(w, "  %-8s %d  %s\n", r.ID, n, r.Title)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RenderMarkdown writes a GitHub-flavoured markdown report.
func RenderMarkdown(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "# Agent Surface Scan Report\n\n")
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Root | `%s` |\n", rep.Root)
	fmt.Fprintf(w, "| Scanned at | %s |\n", rep.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "| Agent-facing files | %d |\n", rep.Files)
	fmt.Fprintf(w, "| Findings | %d |\n", len(rep.Matches))
	fmt.Fprintf(w, "| Score | %d |\n", rep.Score)
	fmt.Fprintf(w, "| Risk | **%s** |\n\n", rep.TopRisk())

	if len(rep.Matches) == 0 {
		fmt.Fprintf(w, "No findings.\n")
		return
	}

	fmt.Fprintf(w, "## Findings\n\n")
	cur := ""
	for _, m := range rep.Matches {
		if m.File != cur {
			cur = m.File
			fmt.Fprintf(w, "### %s\n\n", m.File)
		}
		fmt.Fprintf(w, "**%s** — `%s` (L%d, %s, %s)\n\n", m.Title, m.RuleID, m.Line, strings.ToUpper(string(m.Severity)), m.ASI)
		fmt.Fprintf(w, "%s\n\n", m.Message)
		if m.Evidence != "" {
			fmt.Fprintf(w, "```text\n%s\n```\n\n", m.Evidence)
		}
		fmt.Fprintf(w, "**Fix:** %s\n\n", m.Fix)
	}

	fmt.Fprintf(w, "## Rule summary\n\n| Rule | Severity | ASI | Count |\n|---|---|---|---|\n")
	for _, r := range rules.All() {
		if n := rep.RuleStats[r.ID]; n > 0 {
			fmt.Fprintf(w, "| %s | %s | %s | %d |\n", r.ID, string(r.Severity), r.ASI, n)
		}
	}
	fmt.Fprintf(w, "\n")
}

// RenderJSON writes a machine-readable report.
func RenderJSON(w io.Writer, rep *Report) error {
	type jsonFile struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	}
	type jsonMatch struct {
		RuleID   string `json:"ruleId"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		ASI      string `json:"asi"`
		File     string `json:"file"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
		Evidence string `json:"evidence"`
		Message  string `json:"message"`
		Fix      string `json:"fix"`
	}
	type jsonReport struct {
		Schema    int            `json:"schema"`
		Tool      string         `json:"tool"`
		Version   string         `json:"version"`
		Root      string         `json:"root"`
		ScannedAt string         `json:"scannedAt"`
		Files     int            `json:"files"`
		FileKinds map[string]int `json:"fileKinds"`
		Skipped   []string       `json:"skipped"`
		Findings  []jsonMatch    `json:"findings"`
		Score     int            `json:"score"`
		Risk      string         `json:"risk"`
	}
	out := jsonReport{
		Schema: 1, Tool: "agent-surface-scan", Version: Version,
		Root: rep.Root, ScannedAt: rep.ScannedAt.Format(time.RFC3339),
		Files: rep.Files, FileKinds: map[string]int{}, Skipped: rep.Skipped,
		Score: rep.Score, Risk: rep.TopRisk(),
	}
	for k, v := range rep.FileKinds {
		out.FileKinds[string(k)] = v
	}
	for _, m := range rep.Matches {
		out.Findings = append(out.Findings, jsonMatch{
			RuleID: m.RuleID, Title: m.Title, Severity: string(m.Severity), ASI: m.ASI,
			File: m.File, Line: m.Line, Column: m.Column,
			Evidence: m.Evidence, Message: m.Message, Fix: m.Fix,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// sarifLevel maps a severity to a SARIF level.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.Critical:
		return "error"
	case model.High, model.Medium:
		return "warning"
	default:
		return "note"
	}
}

// RenderSARIF writes a SARIF 2.1.0 document.
func RenderSARIF(w io.Writer, rep *Report) error {
	type rule struct {
		ID               string                `json:"id"`
		Name             string                `json:"name"`
		ShortDescription struct{ Text string } `json:"shortDescription"`
		FullDescription  struct{ Text string } `json:"fullDescription"`
		Properties       struct {
			SecuritySeverity string   `json:"security-severity"`
			Tags             []string `json:"tags"`
		} `json:"properties"`
	}
	type region struct {
		StartLine   int `json:"startLine,omitempty"`
		StartColumn int `json:"startColumn,omitempty"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct{ URI string } `json:"artifactLocation"`
			Region           region               `json:"region"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string                `json:"ruleId"`
		RuleIndex int                   `json:"ruleIndex"`
		Level     string                `json:"level"`
		Message   struct{ Text string } `json:"message"`
		Locations []location            `json:"locations"`
	}
	type run struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				Version        string `json:"version"`
				InformationURI string `json:"informationUri"`
				Rules          []rule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}
	type sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	all := rules.All()
	idx := map[string]int{}
	var doc sarif
	doc.Schema = "https://json.schemastore.org/sarif-2.1.0.json"
	doc.Version = "2.1.0"
	var r run
	r.Tool.Driver.Name = "agent-surface-scan"
	r.Tool.Driver.Version = Version
	r.Tool.Driver.InformationURI = "https://github.com/CN-001/agent-surface-scan"
	for i, ru := range all {
		idx[ru.ID] = i
		var d rule
		d.ID = ru.ID
		d.Name = ru.Title
		d.ShortDescription.Text = ru.Title
		d.FullDescription.Text = ru.Summary
		d.Properties.SecuritySeverity = fmt.Sprintf("%.1f", float64(ru.Severity.Weight()))
		d.Properties.Tags = []string{"security", "ai", ru.ASI}
		r.Tool.Driver.Rules = append(r.Tool.Driver.Rules, d)
	}
	for _, m := range rep.Matches {
		var res result
		res.RuleID = m.RuleID
		res.RuleIndex = idx[m.RuleID]
		res.Level = sarifLevel(m.Severity)
		res.Message.Text = m.Message
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = strings.ReplaceAll(m.File, "\\", "/")
		loc.PhysicalLocation.Region.StartLine = m.Line
		if m.Column > 0 {
			loc.PhysicalLocation.Region.StartColumn = m.Column
		}
		res.Locations = []location{loc}
		r.Results = append(r.Results, res)
	}
	doc.Runs = []run{r}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
