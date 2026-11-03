package scan

import (
	"path/filepath"
	"testing"

	"agent-surface-scan/internal/model"
)

func TestRepoScan(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "repo"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"AGX-001": true, // README curl|bash
		"AGE-001": true, // README exfil
		"AGC-002": true, // .mcp.json autoApprove
		"AGS-001": true, // SKILL.md ghp_ token
		"AGI-001": true, // ISSUE_TEMPLATE override
		"AGD-001": true, // docs/guide.md shortener
	}
	for _, m := range rep.Matches {
		want[m.RuleID] = false
	}
	for id, missing := range want {
		if missing {
			t.Errorf("expected finding for rule %s", id)
		}
	}
	if !rep.Risk.AtLeast(model.High) {
		t.Errorf("expected risk >= high, got %s", rep.Risk)
	}
	if rep.Files < 6 {
		t.Errorf("expected at least 6 agent-facing files, got %d", rep.Files)
	}
}

func TestBenignCorpus(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus", "benign"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range rep.Matches {
		if m.Severity.AtLeast(model.High) {
			t.Errorf("benign corpus must not produce high/critical findings, got %s in %s", m.RuleID, m.File)
		}
	}
}

func TestMaliciousCorpus(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus", "malicious"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"AGI-001": true, "AGI-002": true, "AGI-003": true, "AGX-001": true,
		"AGX-003": true, "AGE-001": true, "AGE-002": true, "AGEV-002": true,
		"AGD-001": true, "AGS-001": true, "AGC-001": true, "AGC-002": true,
	}
	for _, m := range rep.Matches {
		want[m.RuleID] = false
	}
	for id, missing := range want {
		if missing {
			t.Errorf("expected finding for rule %s", id)
		}
	}
}
