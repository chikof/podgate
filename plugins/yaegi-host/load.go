package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing/fstest"
)

// Bounds on what the host reads of a plugin directory, so a directory cannot fill the host's
// memory.
const (
	maxSourceFiles = 4096
	maxSourceBytes = 32 << 20
)

// goPath is the GOPATH of the interpreter. It names a place in the in-memory file system below,
// not on the disk.
const goPath = "gp"

// Source is one vendored Traefik plugin: its sources in memory, and the import path they are
// served under.
type Source struct {
	// Import is the plugin's import path, from `import:` of its .traefik.yml.
	Import string
	// FS holds the plugin's .go files (and its vendor directory) under goPath/src/<Import>.
	FS fs.FS
}

// readManifest reads `type` and `import` of the .traefik.yml, the two keys the host needs. The
// file is YAML, but both are top level scalars, so a line scan reads them and the host needs no
// YAML parser; other keys (summary, testData, ...) are the catalog's and are ignored.
func readManifest(dir string) (typ, importPath string, err error) {
	data, err := os.ReadFile(filepath.Join(dir, ".traefik.yml"))
	if err != nil {
		return "", "", fmt.Errorf("the plugin directory has no readable .traefik.yml: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != key || key == "" {
			continue // indented (nested) or not a key
		}
		value, _, _ = strings.Cut(value, " #")
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch key {
		case "type":
			typ = value
		case "import":
			importPath = value
		}
	}
	if typ != "middleware" {
		return "", "", fmt.Errorf(".traefik.yml: type is %q; only middleware plugins are supported", typ)
	}
	if importPath == "" || checkImportPath(importPath) != nil {
		return "", "", fmt.Errorf(".traefik.yml: import %q is not a module path such as github.com/acme/plugin", importPath)
	}
	return typ, importPath, nil
}

func checkImportPath(p string) error {
	first, _, _ := strings.Cut(p, "/")
	if !strings.Contains(first, ".") || strings.Contains(p, "..") || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("bad import path %q", p)
	}
	return nil
}

// LoadSource reads the plugin directory: its manifest, its .go files and the imports of every
// one of them, and refuses the plugin when an import is not allowed. Nothing in it runs.
//
// Only regular .go files are read (not tests, symbolic links, testdata or dot directories), so
// what the interpreter can import is exactly what this function saw and checked.
func LoadSource(dir string) (*Source, error) {
	_, importPath, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	files := fstest.MapFS{}
	imports := map[string][]string{}
	var total int64
	fset := token.NewFileSet()
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !d.Type().IsRegular() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if len(files) >= maxSourceFiles {
			return fmt.Errorf("the plugin has more than %d Go files", maxSourceFiles)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if total += int64(len(data)); total > maxSourceBytes {
			return fmt.Errorf("the plugin's Go files are larger than %d bytes", maxSourceBytes)
		}
		parsed, err := parser.ParseFile(fset, rel, data, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("cannot parse %s: %w", rel, err)
		}
		for _, spec := range parsed.Imports {
			unquoted, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: bad import %s", rel, spec.Path.Value)
			}
			imports[unquoted] = append(imports[unquoted], filepath.ToSlash(rel))
		}
		files[path.Join(goPath, "src", importPath, filepath.ToSlash(rel))] = &fstest.MapFile{Data: data, Mode: 0o444}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("the plugin directory has no Go files")
	}
	if err := refusedImports(imports); err != nil {
		return nil, err
	}
	return &Source{Import: importPath, FS: files}, nil
}
