package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePlugin(t *testing.T, manifest string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, ".traefik.yml"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestManifest(t *testing.T) {
	good := "displayName: X # a comment\ntype: \"middleware\"\nimport: 'github.com/acme/plug'  # where\ntestData:\n  type: other\n  import: nested.example/ignored\n"
	dir := writePlugin(t, good, map[string]string{"p.go": "package plug\n"})
	typ, imp, err := readManifest(dir)
	if err != nil || typ != "middleware" || imp != "github.com/acme/plug" {
		t.Fatalf("readManifest = %q %q %v", typ, imp, err)
	}
	for manifest, want := range map[string]string{
		"type: middleware\n":                        "import",
		"type: provider\nimport: github.com/a/b\n":  "only middleware plugins",
		"import: github.com/a/b\n":                  "only middleware plugins",
		"type: middleware\nimport: plug\n":          "not a module path",
		"type: middleware\nimport: a.b/../../etc\n": "not a module path",
	} {
		dir := writePlugin(t, manifest, map[string]string{"p.go": "package plug\n"})
		if _, _, err := readManifest(dir); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("manifest %q: err = %v, want %q", manifest, err, want)
		}
	}
	if _, err := LoadSource(writePlugin(t, "", map[string]string{"p.go": "package plug\n"})); err == nil || !strings.Contains(err.Error(), ".traefik.yml") {
		t.Errorf("no manifest: err = %v", err)
	}
}

func TestLoadSourceReadsOnlyPluginGoFiles(t *testing.T) {
	dir := writePlugin(t, "type: middleware\nimport: github.com/acme/plug\n", map[string]string{
		"plug.go":              "package plug\nimport \"strings\"\nvar _ = strings.ToUpper\n",
		"plug_test.go":         "package plug\nimport \"os/exec\"\n", // tests are never loaded
		"testdata/x.go":        "package x\nimport \"os/exec\"\n",
		".git/hooks/x.go":      "package x\nimport \"os/exec\"\n",
		"notes.txt":            "import \"os/exec\"",
		"vendor/a.b/c/c.go":    "package c\n",
		"vendor/a.b/c/skip.sh": "#!/bin/sh\n",
	})
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.go")); err != nil {
		t.Fatal(err)
	}
	source, err := LoadSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"plug.go", "vendor/a.b/c/c.go"} {
		if _, err := source.FS.Open("gp/src/github.com/acme/plug/" + name); err != nil {
			t.Errorf("%s was not loaded: %v", name, err)
		}
	}
	for _, name := range []string{"plug_test.go", "testdata/x.go", "link.go", "notes.txt", "vendor/a.b/c/skip.sh"} {
		if _, err := source.FS.Open("gp/src/github.com/acme/plug/" + name); err == nil {
			t.Errorf("%s was loaded", name)
		}
	}
}

func TestLoadSourceRefusesBrokenGo(t *testing.T) {
	dir := writePlugin(t, "type: middleware\nimport: github.com/acme/plug\n", map[string]string{"plug.go": "package plug\nimport (\n"})
	if _, err := LoadSource(dir); err == nil || !strings.Contains(err.Error(), "cannot parse plug.go") {
		t.Fatalf("err = %v", err)
	}
}

func TestBrokenPluginsFailAtLoad(t *testing.T) {
	for name, src := range map[string]string{
		"no CreateConfig": "package plug\nfunc New() {}\n",
		"wrong New":       "package plug\ntype C struct{}\nfunc CreateConfig() *C { return &C{} }\nfunc New(s string) {}\n",
		"type error":      "package plug\nfunc CreateConfig() int { return \"x\" }\n",
	} {
		dir := writePlugin(t, "type: middleware\nimport: github.com/acme/plug\n", map[string]string{"plug.go": src})
		source, err := LoadSource(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := NewHost("plug", source); err == nil {
			t.Errorf("%s: the host started", name)
		}
	}
}
