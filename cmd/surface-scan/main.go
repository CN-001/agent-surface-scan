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
  --rules <id[,id...]>                run only these rules (e.g. AGX-001,AGS-001)
  --skip-rules <id[,id...]>           never run these rules
  --min-severity <severity>           hide findings below this severity
  --list                              print discovered files and exit
`)
}

// scanFlags holds the parsed flags of the scan command.
type scanFlags struct {
	format      string
	outPath     string
	failOn      string
	maxMB       float64
	exclude     string
	allowlist   string
	rules       string
	skipRules   string
	minSeverity string
	list        bool
	help        bool
	root        string
}

func defaultScanFlags() scanFlags {
	return scanFlags{
		format:    "text",
		failOn:    "high",
		maxMB:     1.0,
		allowlist: ".surface-scanignore",
		root:      ".",
	}
}

// parseScanArgs parses scan flags; flags may appear before or after the path.
func parseScanArgs(args []string) (scanFlags, error) {
	f := defaultScanFlags()
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		value := func(name string) (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag --%s requires a value", name)
			}
			i++
			return args[i], nil
		}
		switch a {
		case "--format":
			v, err := value("format")
			if err != nil {
				return f, err
			}
			f.format = v
		case "--out":
			v, err := value("out")
			if err != nil {
				return f, err
			}
			f.outPath = v
		case "--fail-on":
			v, err := value("fail-on")
			if err != nil {
				return f, err
			}
			f.failOn = v
		case "--max-size":
			v, err := value("max-size")
			if err != nil {
				return f, err
			}
			n, perr := strconv.ParseFloat(v, 64)
			if perr != nil {
				return f, perr
			}
			f.maxMB = n
		case "--exclude":
			v, err := value("exclude")
			if err != nil {
				return f, err
			}
			f.exclude = v
		case "--allowlist":
			v, err := value("allowlist")
			if err != nil {
				return f, err
			}
			f.allowlist = v
		case "--rules":
			v, err := value("rules")
			if err != nil {
				return f, err
			}
			f.rules = v
		case "--skip-rules":
			v, err := value("skip-rules")
			if err != nil {
				return f, err
			}
			f.skipRules = v
		case "--min-severity":
			v, err := value("min-severity")
			if err != nil {
				return f, err
			}
			f.minSeverity = v
		case "--list":
			f.list = true
		case "-h", "--help":
			f.help = true
		default:
			if strings.HasPrefix(a, "-") {
				return f, fmt.Errorf("unknown flag %s", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) > 1 {
		return f, fmt.Errorf("scan accepts at most one path argument")
	}
	if len(pos) == 1 {
		f.root = pos[0]
	}
	return f, nil
}

func cmdScan(args []string) int {
	f, err := parseScanArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if f.help {
		usage(os.Stdout)
		return 0
	}

	threshold, err := model.ParseSeverity(f.failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	switch f.format {
	case "text", "markdown", "json", "sarif":
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q\n", f.format)
		return 2
	}
	if f.minSeverity != "" {
		if _, err := model.ParseSeverity(f.minSeverity); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	abs, err := filepath.Abs(f.root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	opts := scan.Options{MaxSizeBytes: int64(f.maxMB * 1024 * 1024)}
	if f.exclude != "" {
		for _, p := range strings.Split(f.exclude, ",") {
			if p = strings.TrimSpace(p); p != "" {
				opts.Exclude = append(opts.Exclude, p)
			}
		}
	}
	if f.allowlist != "none" && f.allowlist != "" {
		opts.AllowlistPath = f.allowlist
	}
	for _, id := range strings.Split(f.rules, ",") {
		if id = strings.TrimSpace(id); id != "" {
			opts.Rules = append(opts.Rules, id)
		}
	}
	for _, id := range strings.Split(f.skipRules, ",") {
		if id = strings.TrimSpace(id); id != "" {
			opts.SkipRules = append(opts.SkipRules, id)
		}
	}
	opts.MinSeverity = f.minSeverity
	if f.list {
		files, skipped, err := scan.Discover(abs, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, file := range files {
			fmt.Printf("%-12s %s\n", file.Kind, file.Path)
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
	if f.outPath != "" {
		outFile, ferr := os.Create(f.outPath)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, ferr)
			return 1
		}
		defer outFile.Close()
		out = outFile
	} else {
		out = os.Stdout
	}

	switch f.format {
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
		fmt.Fprintf(os.Stderr, "unknown format %q\n", f.format)
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
