// Package model defines the shared data types for agent-surface-scan.
package model

import (
	"fmt"
	"strings"
)

// Severity ranks a finding. Order: critical > high > medium > low > info.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

var severityWeight = map[Severity]int{
	Critical: 10,
	High:     5,
	Medium:   2,
	Low:      1,
	Info:     0,
}

var severityRank = map[Severity]int{
	Critical: 4,
	High:     3,
	Medium:   2,
	Low:      1,
	Info:     0,
}

// Weight returns the numeric weight used for aggregate scoring.
func (s Severity) Weight() int { return severityWeight[s] }

// AtLeast reports whether s ranks at least as severe as t.
func (s Severity) AtLeast(t Severity) bool { return severityRank[s] >= severityRank[t] }

// ParseSeverity parses a user supplied severity name.
func ParseSeverity(v string) (Severity, error) {
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		if strings.EqualFold(string(s), v) {
			return s, nil
		}
	}
	return "", fmt.Errorf("unknown severity %q (want critical|high|medium|low|info)", v)
}

// FileKind classifies an agent-consumed file.
type FileKind string

const (
	KindInstructions  FileKind = "instructions"   // AGENTS.md, CLAUDE.md, .cursorrules, ...
	KindReadme        FileKind = "readme"         // README.md / README.*
	KindContributing  FileKind = "contributing"   // CONTRIBUTING.md
	KindSecurity      FileKind = "security"       // SECURITY.md
	KindIssueTemplate FileKind = "issue-template" // .github/ISSUE_TEMPLATE/**
	KindPRTemplate    FileKind = "pr-template"    // .github/PULL_REQUEST_TEMPLATE*
	KindMCPConfig     FileKind = "mcp-config"     // .mcp.json, .cursor/mcp.json, mcp.json
	KindSkill         FileKind = "skill"          // */SKILL.md
	KindDoc           FileKind = "doc"            // docs/**/*.md and other markdown fed to agents
)

// File is one agent-consumed file inside the scanned tree.
type File struct {
	Path  string   // slash-separated path relative to the scan root
	Abs   string   // absolute path
	Kind  FileKind // classification
	Raw   string   // full file content (UTF-8, BOM stripped)
	Lines []string // lines, 1-based via Lines[i-1]
}

// Match is a single finding produced by a rule.
type Match struct {
	RuleID   string
	Title    string
	Severity Severity
	ASI      string // OWASP Agentic Security Initiative category, e.g. ASI01
	File     string // relative path of the offending file
	Line     int    // 1-based
	Column   int    // 1-based byte column
	Evidence string // the offending line, trimmed
	Message  string // what was detected
	Fix      string // remediation suggestion
}
