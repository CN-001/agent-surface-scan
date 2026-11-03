package scan

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/CN-001/agent-surface-scan/internal/model"
)

// Options controls a scan.
type Options struct {
	MaxSizeBytes  int64    // skip files larger than this (0 = default 1 MiB)
	Exclude       []string // path patterns to exclude (slash-separated, glob allowed)
	AllowlistPath string   // .surface-scanignore style file ("" disables)
	Rules         []string // only run these rule IDs (empty = all)
	SkipRules     []string // never run these rule IDs
	MinSeverity   string   // hide findings below this severity ("" = show all)
}

// DefaultMaxSizeBytes is the default per-file size limit.
const DefaultMaxSizeBytes = 1 << 20 // 1 MiB

var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, "target": true, "out": true, "obj": true,
	".next": true, ".nuxt": true, ".venv": true, "venv": true, "__pycache__": true,
	".cache": true, ".idea": true, ".vscode": true, "coverage": true, ".dart_tool": true,
	"Pods": true, ".gradle": true, ".terraform": true, "bower_components": true,
	".turbo": true, ".parcel-cache": true,
}

// exactAgentFiles maps basenames to their kind.
var exactAgentFiles = map[string]model.FileKind{
	"AGENTS.md":       model.KindInstructions,
	"CLAUDE.md":       model.KindInstructions,
	".cursorrules":    model.KindInstructions,
	".windsurfrules":  model.KindInstructions,
	"COPILOT.md":      model.KindInstructions,
	"README.md":       model.KindReadme,
	"CONTRIBUTING.md": model.KindContributing,
	"SECURITY.md":     model.KindSecurity,
	".mcp.json":       model.KindMCPConfig,
}

func classify(rel, base string) (model.FileKind, bool) {
	if k, ok := exactAgentFiles[base]; ok {
		return k, true
	}
	lbase := strings.ToLower(base)
	switch {
	case strings.HasPrefix(lbase, "readme."):
		return model.KindReadme, true
	case strings.HasPrefix(lbase, "contributing."):
		return model.KindContributing, true
	case strings.HasPrefix(lbase, "security."):
		return model.KindSecurity, true
	}
	norm := strings.ReplaceAll(rel, "\\", "/")
	segs := strings.Split(norm, "/")

	// SKILL.md under any directory named skills/ (or agent-scoped skill dirs).
	if strings.EqualFold(base, "SKILL.md") {
		for _, s := range segs[:len(segs)-1] {
			if s == "skills" || s == ".claude" || s == ".cursor" || s == ".agents" || s == ".codex" || s == ".dsh" {
				return model.KindSkill, true
			}
		}
	}

	// .github and .cursor conventions at any depth.
	for i, s := range segs {
		rest := strings.Join(segs[i+1:], "/")
		switch {
		case s == ".github" && (rest == "copilot-instructions.md" || rest == "AGENTS.md"):
			return model.KindInstructions, true
		case s == ".github" && strings.HasPrefix(rest, "ISSUE_TEMPLATE/") &&
			(strings.HasSuffix(lbase, ".md") || strings.HasSuffix(lbase, ".yml") || strings.HasSuffix(lbase, ".yaml")):
			return model.KindIssueTemplate, true
		case s == ".github" && strings.HasPrefix(rest, "PULL_REQUEST_TEMPLATE") &&
			(strings.HasSuffix(lbase, ".md") || strings.HasSuffix(lbase, ".yml") || strings.HasSuffix(lbase, ".yaml")):
			return model.KindPRTemplate, true
		case s == ".cursor" && strings.HasPrefix(rest, "rules/") &&
			(strings.HasSuffix(lbase, ".md") || strings.HasSuffix(lbase, ".mdc")):
			return model.KindInstructions, true
		case s == ".cursor" && rest == "mcp.json":
			return model.KindMCPConfig, true
		}
	}

	switch {
	case norm == "mcp.json" || norm == ".mcp.json":
		return model.KindMCPConfig, true
	case strings.HasSuffix(lbase, ".md") && hasSegment(segs, "docs"):
		return model.KindDoc, true
	}
	return "", false
}

// hasSegment reports whether any path segment equals want.
func hasSegment(segs []string, want string) bool {
	for _, s := range segs {
		if s == want {
			return true
		}
	}
	return false
}

// excluded reports whether a slash-separated path matches an exclusion pattern.
// A pattern without globs also matches the whole subtree below that prefix.
func excluded(rel string, pats []string) bool {
	for _, p := range pats {
		p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
		if p == "" {
			continue
		}
		if p == rel || strings.HasPrefix(rel, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
		if ok, err := path.Match(p, rel); err == nil && ok {
			return true
		}
	}
	return false
}

// Discover walks root and returns every agent-facing file plus skipped paths.
func Discover(root string, opts Options) ([]model.File, []string, error) {
	maxSize := opts.MaxSizeBytes
	if maxSize <= 0 {
		maxSize = DefaultMaxSizeBytes
	}
	var files []model.File
	var skipped []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort: skip unreadable entries
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		kind, ok := classify(filepath.ToSlash(rel), d.Name())
		if !ok {
			return nil
		}
		if excluded(filepath.ToSlash(rel), opts.Exclude) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if info.Size() > maxSize {
			skipped = append(skipped, rel+" (too large)")
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			skipped = append(skipped, rel+" (unreadable)")
			return nil
		}
		if len(raw) > 0 && raw[0] == 0xEF && len(raw) > 2 && raw[1] == 0xBB && raw[2] == 0xBF {
			raw = raw[3:] // strip UTF-8 BOM
		}
		if looksBinary(raw) || !utf8.Valid(raw) {
			skipped = append(skipped, rel+" (binary / non-UTF8)")
			return nil
		}
		// Normalize line endings once so Raw and Lines share the same offsets.
		text := strings.ReplaceAll(string(raw), "\r\n", "\n")
		lines := strings.Split(text, "\n")
		files = append(files, model.File{
			Path:  filepath.ToSlash(rel),
			Abs:   path,
			Kind:  kind,
			Raw:   text,
			Lines: lines,
		})
		return nil
	})
	if err != nil {
		return nil, skipped, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Strings(skipped)
	return files, skipped, nil
}

func looksBinary(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}
