// Command surface-scan scans the agent-facing attack surface of a repository.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/CN-001/agent-surface-scan/internal/model"
	"github.com/CN-001/agent-surface-scan/internal/rules"
	"github.com/CN-001/agent-surface-scan/internal/scan"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "scan":
		code = cmdScan(os.Args[2:])
	case "init-ci":
		code = cmdInitCI(os.Args[2:])
	case "rules":
		code = cmdRules()
	case "version":
		fmt.Println(scan.Version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		code = 2
	}
	if code != 0 {
		os.Exit(code)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `agent-surface-scan — scan the AI agent attack surface of a repository

Usage:
  surface-scan scan [path] [flags]   scan a repository (default: current dir)
  surface-scan init-ci [path]        write a GitHub Actions workflow template
  surface-scan rules                 list all detection rules
  surface-scan version               print the version

Scan flags (may appear before or after the path):
  --format text|markdown|json|sarif   output format (default: text)
  --out <file>                        write report to a file instead of stdout
  --fail-on <severity>                exit code 2 when any finding is at least
                                      this severe (default: high)
  --max-size <MB>                     skip files larger than N MiB (default: 1)
  --exclude <pattern[,pattern...]>    exclude paths (glob or prefix, e.g. testdata,docs)
  --allowlist <file|none>             allowlist file (default: .surface-scanignore)
  --list                              print discovered files and exit
`)
}

func cmdScan(args []string) int {
	format := "text"
	outPath := ""
	failOn := "high"
	maxMB := 1.0
	exclude := ""
	allowlist := ".surface-scanignore"
	list := false
	var pos []string

	i := 0
	need := func(name string) (string, bool) {
		if i+1 >= len(args) {
			fmt.Fprintf(os.Stderr, "flag --%s requires a value\n", name)
			return "", false
		}
		i++
		return args[i], true
	}
	for ; i < len(args); i++ {
		switch a := args[i]; a {
		case "--format":
			v, ok := need("format")
			if !ok {
				return 2
			}
			format = v
		case "--out":
			v, ok := need("out")
			if !ok {
				return 2
			}
			outPath = v
		case "--fail-on":
			v, ok := need("fail-on")
			if !ok {
				return 2
			}
			failOn = v
		case "--max-size":
			v, ok := need("max-size")
			if !ok {
				return 2
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			maxMB = f
		case "--exclude":
			v, ok := need("exclude")
			if !ok {
				return 2
			}
			exclude = v
		case "--allowlist":
			v, ok := need("allowlist")
			if !ok {
				return 2
			}
			allowlist = v
		case "--list":
			list = true
		case "-h", "--help":
			usage(os.Stdout)
			return 0
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "unknown flag %s\n", a)
				return 2
			}
			pos = append(pos, a)
		}
	}
	if len(pos) > 1 {
		fmt.Fprintln(os.Stderr, "scan accepts at most one path argument")
		return 2
	}

	threshold, err := model.ParseSeverity(failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	root := "."
	if len(pos) == 1 {
		root = pos[0]
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	opts := scan.Options{MaxSizeBytes: int64(maxMB * 1024 * 1024)}
	if exclude != "" {
		for _, p := range strings.Split(exclude, ",") {
			if p = strings.TrimSpace(p); p != "" {
				opts.Exclude = append(opts.Exclude, p)
			}
		}
	}
	if allowlist != "none" && allowlist != "" {
		opts.AllowlistPath = allowlist
	}
	if list {
		files, skipped, err := scan.Discover(abs, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, f := range files {
			fmt.Printf("%-12s %s\n", f.Kind, f.Path)
		}
		for _, s := range skipped {
			fmt.Printf("skipped      %s\n", s)
		}
		return 0
	}

	rep, err := scan.Run(abs, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	var out *os.File
	if outPath != "" {
		f, ferr := os.Create(outPath)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, ferr)
			return 1
		}
		defer f.Close()
		out = f
	} else {
		out = os.Stdout
	}

	switch format {
	case "text":
		scan.RenderText(out, rep)
	case "markdown":
		scan.RenderMarkdown(out, rep)
	case "json":
		if err := scan.RenderJSON(out, rep); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "sarif":
		if err := scan.RenderSARIF(out, rep); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q\n", format)
		return 2
	}

	if len(rep.Matches) > 0 && rep.Risk.AtLeast(threshold) {
		fmt.Fprintf(os.Stderr, "\nfailed: risk %s reaches --fail-on %s (%s)\n", rep.TopRisk(), threshold, rep.Summary())
		return 2
	}
	return 0
}

const ciTemplate = `# Agent-surface-scan: scan the AI agent attack surface of this repository.
# Runs on every push and pull request and uploads results as SARIF.
name: agent-surface-scan

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.24.x"

      - name: Build surface-scan
        run: |
          git clone --depth 1 https://github.com/CN-001/agent-surface-scan.git /tmp/agent-surface-scan
          cd /tmp/agent-surface-scan
          go build -o "$RUNNER_TEMP/surface-scan" ./cmd/surface-scan

      - name: Scan agent-facing surface
        run: |
          "$RUNNER_TEMP/surface-scan" scan . --format sarif --out results.sarif --fail-on high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
`

func cmdInitCI(args []string) int {
	fs := flag.NewFlagSet("init-ci", flag.ContinueOnError)
	force := fs.Bool("force", false, "overwrite an existing workflow file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	dest := filepath.Join(root, ".github", "workflows", "surface-scan.yml")
	if _, err := os.Stat(dest); err == nil && !*force {
		fmt.Fprintf(os.Stderr, "%s already exists (use --force to overwrite)\n", dest)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(dest, []byte(ciTemplate), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote %s (template for https://github.com/CN-001/agent-surface-scan)\n", dest)
	return 0
}

func cmdRules() int {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSeverity\tASI\tTitle")
	for _, r := range rules.All() {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.ASI, r.Title)
	}
	w.Flush()
	return 0
}
