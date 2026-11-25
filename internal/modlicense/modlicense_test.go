package modlicense

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := map[Family]string{
		MIT:           "MIT License\n\nPermission is hereby granted, free of charge, to any person",
		Apache2:       "                                 Apache License\n                           Version 2.0, January 2004",
		BSD:           "Redistribution and use in source and binary forms, with or without modification",
		ISC:           "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted",
		MPL2:          "Mozilla Public License Version 2.0\n\n1. Definitions",
		EPL2:          "Eclipse Public License - v 2.0",
		Unlicense:     "This is free and unencumbered software released into the public domain.",
		GPL:           "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007",
		LGPL:          "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3",
		AGPL:          "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3",
		SSPL:          "Server Side Public License\nVERSION 1, OCTOBER 16, 2018",
		BSL:           "Business Source License 1.1",
		CommonsClause: "MIT License\n\nPermission is hereby granted, free of charge\n\n\"Commons Clause\" License Condition v1.0",
		Unknown:       "You may do whatever you like.",
	}
	for want, text := range cases {
		if got := Detect(text); got != want {
			t.Errorf("Detect(%q) = %s, want %s", text[:20], got, want)
		}
	}
}

// EPL-2.0 and MPL-2.0 quote the GPL as a possible Secondary License; the
// quotation must not classify the file as GPL.
// The ISC text ships with and without "and/or"; coder/websocket's copy omits it.
func TestISCWithoutAndOr(t *testing.T) {
	if got := Detect("Copyright (c) 2025 Coder\n\nPermission to use, copy, modify, and distribute this software for any purpose with or without fee is hereby granted"); got != ISC {
		t.Errorf("Detect = %s, want ISC", got)
	}
}

func TestSecondaryLicenseQuotationIsNotGPL(t *testing.T) {
	epl := "Eclipse Public License - v 2.0\n... Secondary License means either the GNU General Public License, Version 2.0, or any later versions of that license ..."
	if got := Detect(epl); got != EPL2 {
		t.Errorf("EPL text classified as %s", got)
	}
	mpl := "Mozilla Public License Version 2.0\n1.12. Secondary License means either the GNU General Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1 ..."
	if got := Detect(mpl); got != MPL2 {
		t.Errorf("MPL text classified as %s", got)
	}
}

func TestPolicy(t *testing.T) {
	for _, f := range Allowed {
		if !IsAllowed(f) {
			t.Errorf("%s should be allowed", f)
		}
	}
	// MPL-2.0, EPL-2.0 and Unlicense are detected so a report can name them,
	// but burrow's policy allows only MIT, Apache-2.0, BSD and ISC.
	notAllowed := []Family{Unknown, MPL2, EPL2, Unlicense}
	notAllowed = append(notAllowed, Forbidden...)
	for _, f := range notAllowed {
		if IsAllowed(f) {
			t.Errorf("%s should not be allowed", f)
		}
	}
}

func TestParseList(t *testing.T) {
	in := `{"Path":"github.com/happydave/burrow","Main":true,"Dir":"/x"}
{"Path":"b.example/m","Version":"v1.2.0","Dir":"/cache/b"}
{"Path":"a.example/m","Version":"v0.1.0","Dir":"/cache/a"}
`
	mods, err := ParseList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 3 || mods[0].Path != "a.example/m" || !mods[2].Main {
		t.Fatalf("got %+v", mods)
	}
	if _, err := ParseList(strings.NewReader(`{"Path":`)); err == nil {
		t.Error("expected parse error")
	}
}

func fakeModule(t *testing.T, name, licenseName, text string) Module {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if licenseName != "" {
		if err := os.WriteFile(filepath.Join(dir, licenseName), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Module{Path: "example.com/" + name, Version: "v1.0.0", Dir: dir}
}

func TestClassifyAndViolations(t *testing.T) {
	main := Module{Path: "github.com/happydave/burrow", Main: true}
	ok := fakeModule(t, "ok", "LICENSE", "Permission is hereby granted, free of charge")
	copying := fakeModule(t, "copying", "COPYING.txt", "Redistribution and use in source and binary forms")
	bad := fakeModule(t, "bad", "LICENSE.md", "GNU GENERAL PUBLIC LICENSE")
	none := fakeModule(t, "none", "", "")
	odd := fakeModule(t, "odd", "LICENSE", "Do what thou wilt.")

	reports := Classify([]Module{main, ok, copying, bad, none, odd})
	if len(reports) != 5 {
		t.Fatalf("main module should be skipped; got %d reports", len(reports))
	}
	want := map[string]Family{
		"example.com/ok": MIT, "example.com/copying": BSD, "example.com/bad": GPL,
		"example.com/none": Unknown, "example.com/odd": Unknown,
	}
	for _, r := range reports {
		if r.Family != want[r.Module.Path] {
			t.Errorf("%s classified %s, want %s", r.Module.Path, r.Family, want[r.Module.Path])
		}
	}
	v := Violations(reports)
	var paths []string
	for _, r := range v {
		paths = append(paths, r.Module.Path)
	}
	if got := strings.Join(paths, ","); got != "example.com/bad,example.com/none,example.com/odd" {
		t.Errorf("violations = %s", got)
	}
}

func TestReasonNamesTheFix(t *testing.T) {
	missing := Report{Module: Module{Path: "example.com/gone", Dir: "/cache/gone"}, Family: Unknown}
	if got := missing.Reason(); !strings.Contains(got, "go mod download") || !strings.Contains(got, "/cache/gone") {
		t.Errorf("a module with no licence file should name its directory and go mod download: %q", got)
	}
	gpl := Report{Module: Module{Path: "example.com/gpl"}, File: "/x/LICENSE", Family: GPL}
	if got := gpl.Reason(); !strings.Contains(got, "GPL") || strings.Contains(got, "go mod download") {
		t.Errorf("a forbidden family should be named, without the cache hint: %q", got)
	}
}

// TestGPLModuleIsAViolation is the gate's negative control: a module carrying
// GPL-3.0 text, fed through the path the whole-graph test uses, is reported.
func TestGPLModuleIsAViolation(t *testing.T) {
	gpl := fakeModule(t, "gpl", "LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007")
	v := Violations(Classify([]Module{gpl}))
	if len(v) != 1 || v[0].Family != GPL {
		t.Fatalf("a GPL-3.0 module should be one GPL violation, got %+v", v)
	}
}

func TestLicenseFilePrefersStableOrder(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"LICENSE.txt", "LICENSE", "COPYING"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := filepath.Base(LicenseFile(dir)); got != "COPYING" {
		t.Errorf("got %s", got)
	}
	if LicenseFile("") != "" || LicenseFile(filepath.Join(dir, "missing")) != "" {
		t.Error("missing dir should yield empty")
	}
}

// TestModuleGraphWithinPolicy is the dependency-licence gate: every module
// compiled into burrow's packages or their tests carries an allowed licence.
func TestModuleGraphWithinPolicy(t *testing.T) {
	ctx := context.Background()
	gomod, err := exec.CommandContext(ctx, "go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	root := filepath.Dir(strings.TrimSpace(string(gomod)))
	mods, err := List(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	reports := Classify(mods)
	// An empty list would pass vacuously; burrow depends on wireguard-go.
	sawWireguard := false
	for _, r := range reports {
		sawWireguard = sawWireguard || r.Module.Path == "golang.zx2c4.com/wireguard"
	}
	if !sawWireguard {
		t.Fatalf("module list lacks golang.zx2c4.com/wireguard (%d modules): run go mod download", len(reports))
	}
	for _, r := range Violations(reports) {
		t.Errorf("%s %s: %s", r.Module.Path, r.Module.Version, r.Reason())
	}
}
