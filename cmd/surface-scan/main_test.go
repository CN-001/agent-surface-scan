package main

import "testing"

func TestParseScanArgsDefaults(t *testing.T) {
	f, err := parseScanArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.format != "text" || f.failOn != "high" || f.maxMB != 1.0 || f.root != "." {
		t.Errorf("unexpected defaults: %+v", f)
	}
	if f.allowlist != ".surface-scanignore" {
		t.Errorf("allowlist default = %q", f.allowlist)
	}
}

func TestParseScanArgsOrder(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want scanFlags
	}{
		{
			name: "flags before path",
			args: []string{"--fail-on", "critical", "--out", "r.json", "repo"},
			want: scanFlags{format: "text", failOn: "critical", maxMB: 1.0, outPath: "r.json", allowlist: ".surface-scanignore", root: "repo"},
		},
		{
			name: "flags after path",
			args: []string{"repo", "--format", "json"},
			want: scanFlags{format: "json", failOn: "high", maxMB: 1.0, allowlist: ".surface-scanignore", root: "repo"},
		},
		{
			name: "exclude allowlist max list",
			args: []string{"--exclude", "testdata,docs", "--allowlist", "none", "--max-size", "2.5", "--list", "."},
			want: scanFlags{format: "text", failOn: "high", maxMB: 2.5, exclude: "testdata,docs", allowlist: "none", list: true, root: "."},
		},
		{
			name: "help flag",
			args: []string{"--help"},
			want: scanFlags{format: "text", failOn: "high", maxMB: 1.0, allowlist: ".surface-scanignore", help: true, root: "."},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseScanArgs(c.args)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestParseScanArgsErrors(t *testing.T) {
	cases := [][]string{
		{"--format"},                  // missing value
		{"--max-size", "abc"},         // invalid number
		{"--unknown"},                 // unknown flag
		{"a", "b"},                    // two paths
		{"--out", "x", "y", "--list"}, // one path ok, but ensure parse works elsewhere
	}
	// last case is actually valid; only the first four must fail
	for i, args := range cases {
		_, err := parseScanArgs(args)
		if i < 4 && err == nil {
			t.Errorf("args %v: expected error", args)
		}
	}
}
