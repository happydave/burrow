// Package modlicense inspects the module graph for licence policy: it lists
// modules, finds each module's licence file, classifies the licence text into
// a family, and applies the project's allow and forbid lists. Derived from
// HoardMQ's package of the same name, by way of Barovis's copy (Apache-2.0/MIT).
package modlicense

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Module is one entry from `go list -m -json all`.
type Module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
}

// Family is a licence family recognised by Detect.
type Family string

// Recognised families. Unknown means the text matched nothing known.
const (
	MIT           Family = "MIT"
	Apache2       Family = "Apache-2.0"
	BSD           Family = "BSD"
	ISC           Family = "ISC"
	MPL2          Family = "MPL-2.0"
	EPL2          Family = "EPL-2.0"
	Unlicense     Family = "Unlicense"
	GPL           Family = "GPL"
	LGPL          Family = "LGPL"
	AGPL          Family = "AGPL"
	SSPL          Family = "SSPL"
	BSL           Family = "BSL"
	CommonsClause Family = "Commons-Clause"
	Unknown       Family = "unknown"
)

// Allowed and Forbidden are the project policy. Anything not in Allowed fails
// the gate too; the Forbidden list exists so the report can name the family.
var (
	Allowed   = []Family{MIT, Apache2, BSD, ISC}
	Forbidden = []Family{GPL, LGPL, AGPL, SSPL, BSL, CommonsClause}
)

// Detect classifies licence text by well-known phrases. Riders that turn a
// permissive file into a forbidden one (Commons Clause, BSL, SSPL) are tested
// first; then the weak-copyleft licences whose text quotes the GPL as a
// "Secondary License" (EPL-2.0, MPL-2.0), so that quotation does not read as
// GPL; then the GPL family; then the permissive families.
func Detect(text string) Family {
	t := strings.ToLower(collapse(text))
	switch {
	case strings.Contains(t, "commons clause"):
		return CommonsClause
	case strings.Contains(t, "business source license"):
		return BSL
	case strings.Contains(t, "server side public license"):
		return SSPL
	case strings.Contains(t, "eclipse public license") && strings.Contains(t, "2.0"):
		return EPL2
	case strings.Contains(t, "mozilla public license") && strings.Contains(t, "2.0"):
		return MPL2
	case strings.Contains(t, "gnu affero general public license"):
		return AGPL
	case strings.Contains(t, "gnu lesser general public license"), strings.Contains(t, "gnu library general public license"):
		return LGPL
	case strings.Contains(t, "gnu general public license"):
		return GPL
	case strings.Contains(t, "apache license") && strings.Contains(t, "version 2.0"):
		return Apache2
	case strings.Contains(t, "this is free and unencumbered software released into the public domain"):
		return Unlicense
	case strings.Contains(t, "permission is hereby granted, free of charge"):
		return MIT
	case strings.Contains(t, "distribute this software for any purpose with or without fee"):
		// ISC, with or without the "and/or" some copies omit.
		return ISC
	case strings.Contains(t, "redistribution and use in source and binary forms"):
		return BSD
	}
	return Unknown
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// IsAllowed reports whether a family passes the policy.
func IsAllowed(f Family) bool {
	for _, a := range Allowed {
		if a == f {
			return true
		}
	}
	return false
}

// List returns the modules whose packages are compiled into this module's
// packages or their tests. The full module graph (`go list -m all`) also
// names modules that graph pruning keeps for version resolution only; those
// ship nothing and are not downloaded, so they are excluded.
func List(ctx context.Context, dir string) ([]Module, error) {
	return list(ctx, dir, true, "./...")
}

func list(ctx context.Context, dir string, withTests bool, pattern string) ([]Module, error) {
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = dir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
	all, err := run("list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}
	mods, err := ParseList(bytes.NewReader(all))
	if err != nil {
		return nil, err
	}
	args := []string{"list", "-deps"}
	if withTests {
		args = append(args, "-test")
	}
	args = append(args, "-f", "{{if .Module}}{{.Module.Path}}{{end}}", pattern)
	used, err := run(args...)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, line := range strings.Split(string(used), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			keep[line] = true
		}
	}
	out := mods[:0]
	for _, m := range mods {
		if m.Main || keep[m.Path] {
			out = append(out, m)
		}
	}
	return out, nil
}

// ParseList decodes the concatenated JSON objects `go list -m -json` prints.
func ParseList(r io.Reader) ([]Module, error) {
	dec := json.NewDecoder(r)
	var mods []Module
	for dec.More() {
		var m Module
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("parse module list: %w", err)
		}
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

// LicenseFile returns the path of the first licence-like file in dir, or ""
// when there is none. Candidates are tried in a fixed order so the result is
// stable.
func LicenseFile(dir string) string {
	if dir == "" {
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		upper := strings.ToUpper(e.Name())
		if strings.HasPrefix(upper, "LICENSE") || strings.HasPrefix(upper, "LICENCE") || strings.HasPrefix(upper, "COPYING") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return filepath.Join(dir, names[0])
}

// Report is one module's classification.
type Report struct {
	Module Module
	File   string
	Family Family
}

// Classify reads each non-main module's licence file and classifies it.
func Classify(mods []Module) []Report {
	var out []Report
	for _, m := range mods {
		if m.Main {
			continue
		}
		r := Report{Module: m, Family: Unknown}
		if r.File = LicenseFile(m.Dir); r.File != "" {
			if data, err := os.ReadFile(r.File); err == nil {
				r.Family = Detect(string(data))
			}
		}
		out = append(out, r)
	}
	return out
}

// Reason says why a report fails the policy. A module with no licence file
// is usually one missing from the module cache, so the reason says how to
// fill it.
func (r Report) Reason() string {
	if r.File == "" {
		return "no licence file found in " + r.Module.Dir + " (run go mod download if the directory is missing)"
	}
	return "licence family " + string(r.Family) + " is not allowed"
}

// Violations returns the reports that fail the policy: a forbidden or unknown
// family, or no licence file at all.
func Violations(reports []Report) []Report {
	var out []Report
	for _, r := range reports {
		if r.File == "" || !IsAllowed(r.Family) {
			out = append(out, r)
		}
	}
	return out
}
