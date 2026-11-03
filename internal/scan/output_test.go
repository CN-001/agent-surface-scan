package scan

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func sampleReport(t *testing.T) *Report {
	t.Helper()
	rep, err := Run(filepath.Join("..", "..", "testdata", "repo"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Matches) == 0 {
		t.Fatal("sample report must contain findings")
	}
	return rep
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, sampleReport(t)); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"schema", "tool", "version", "root", "scannedAt", "files", "findings", "score", "risk"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("JSON report missing key %q", key)
		}
	}
	if doc["tool"] != "agent-surface-scan" {
		t.Errorf("tool = %v", doc["tool"])
	}
}

func TestRenderSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, sampleReport(t)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool    struct{ Driver struct{ Name string } } `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q", doc.Version)
	}
	if len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "agent-surface-scan" {
		t.Errorf("unexpected runs/driver: %+v", doc.Runs)
	}
	for _, r := range doc.Runs[0].Results {
		if r.RuleID == "" {
			t.Error("SARIF result without ruleId")
		}
		if r.Level != "error" && r.Level != "warning" && r.Level != "note" {
			t.Errorf("invalid SARIF level %q", r.Level)
		}
	}
}

func TestRenderTextAndMarkdown(t *testing.T) {
	rep := sampleReport(t)

	var text bytes.Buffer
	RenderText(&text, rep)
	for _, want := range []string{"agent-surface-scan report", "risk:"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text report missing %q", want)
		}
	}

	var md bytes.Buffer
	RenderMarkdown(&md, rep)
	for _, want := range []string{"# Agent Surface Scan Report", "| Field | Value |"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown report missing %q", want)
		}
	}
}
