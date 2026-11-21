package main

import (
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/traefik/yaegi/stdlib"
)

// What an interpreted plugin may import. Yaegi's own sandbox only withholds a few symbols
// (os.Exit and the environment); it still exports os/exec, net, syscall and the file system.
// The host hands the interpreter only the packages below, so everything else fails at load, and
// loader.go refuses the import with a reason before the interpreter sees it.
//
// The set is the pure computation, text, time and HTTP value types a request filter needs. It has
// no way to open a file, a socket or a process, and no reflect or unsafe pointer.
var allowedPackages = []string{
	"bufio", "bytes", "cmp", "container/heap", "container/list", "container/ring", "context",
	"compress/flate", "compress/gzip", "compress/zlib",
	"crypto", "crypto/aes", "crypto/cipher", "crypto/ecdsa", "crypto/ed25519", "crypto/elliptic",
	"crypto/hmac", "crypto/md5", "crypto/rand", "crypto/rsa", "crypto/sha1", "crypto/sha256",
	"crypto/sha512", "crypto/subtle",
	"encoding", "encoding/base32", "encoding/base64", "encoding/binary", "encoding/csv",
	"encoding/hex", "encoding/json", "encoding/pem", "encoding/xml",
	"errors", "fmt", "hash", "hash/adler32", "hash/crc32", "hash/crc64", "hash/fnv", "html",
	"io", "log", "log/slog", "maps", "math", "math/big", "math/bits", "math/cmplx", "math/rand", "math/rand/v2",
	"mime", "mime/multipart", "mime/quotedprintable",
	"net/http", "net/netip", "net/textproto", "net/url",
	"os", "path", "regexp", "regexp/syntax", "slices", "sort", "strconv", "strings", "sync",
	"sync/atomic", "text/tabwriter", "time", "unicode", "unicode/utf16", "unicode/utf8",
}

// Packages named in the refusal of an import, with what each would give a plugin. Anything
// else outside allowedPackages is refused as "not on the allowlist".
var forbiddenReasons = map[string]string{
	"unsafe":                          "unsafe memory access",
	"C":                               "cgo (native code)",
	"os/exec":                         "starting processes",
	"os/signal":                       "process signals",
	"os/user":                         "the host's user database",
	"syscall":                         "system calls",
	"net":                             "network access",
	"net/rpc":                         "network access",
	"net/smtp":                        "network access",
	"net/http/httputil":               "network access",
	"net/http/httptest":               "network access",
	"net/http/cgi":                    "starting processes",
	"net/http/fcgi":                   "network access",
	"crypto/tls":                      "network access",
	"crypto/x509":                     "the host's certificate store",
	"database/sql":                    "network access",
	"log/syslog":                      "network access",
	"plugin":                          "loading native code",
	"reflect":                         "access to unexported memory through reflect",
	"runtime":                         "the Go runtime",
	"runtime/debug":                   "the Go runtime",
	"io/ioutil":                       "file system access",
	"io/fs":                           "file system access",
	"path/filepath":                   "file system access",
	"embed":                           "embedded files",
	"text/template":                   "reading template files",
	"html/template":                   "reading template files",
	"flag":                            "the host's command line",
	"expvar":                          "serving on the host's network",
	"debug/elf":                       "reading executables",
	"testing":                         "the test runner",
	"github.com/traefik/yaegi/interp": "the interpreter itself",
}

// reservedImport is the package the host registers to run a handler under the interpreter's
// cancellation; a plugin has no business importing it.
const reservedImport = "podgate.invalid/hostcall"

// Names of net/http that open connections, serve, or read the host's files. Plugins build
// requests and write responses; they do not send requests. A name listed here is not exported
// to the interpreter, so using it fails when the plugin loads.
var deniedHTTPNames = []string{
	"Client", "DefaultClient", "Transport", "DefaultTransport", "Get", "Head", "Post", "PostForm",
	"ProxyFromEnvironment", "ProxyURL", "Server", "ListenAndServe", "ListenAndServeTLS", "Serve",
	"ServeTLS", "DefaultServeMux", "Handle", "HandleFunc", "Dir", "FS", "FileSystem", "File",
	"FileServer", "FileServerFS", "ServeFile", "ServeFileFS", "NewFileTransport",
	"NewFileTransportFS", "ConnState", "ConnContext", "CloseNotifier", "Hijacker", "HTTP2Config",
	"Protocols", "PushOptions", "Pusher", "NewResponseController", "ResponseController",
}

// The only names of os a plugin gets: the standard streams, and the interpreter's sandboxed
// environment (empty, see newInterpreter).
var allowedOSNames = []string{"Stdout", "Stderr", "Getenv", "LookupEnv", "ErrNotExist", "ErrExist"}

// exports returns a fresh copy of the symbols a plugin may use. A copy, because the
// interpreter writes into the maps it is given.
func exports() map[string]map[string]reflect.Value {
	allowed := map[string]bool{}
	for _, p := range allowedPackages {
		allowed[p] = true
	}
	out := map[string]map[string]reflect.Value{}
	for key, symbols := range stdlib.Symbols {
		importPath := path.Dir(key)
		// "." holds the interpreter's wrapper table for interface arguments.
		if key != "." && !allowed[importPath] {
			continue
		}
		copied := make(map[string]reflect.Value, len(symbols))
		for name, v := range symbols {
			copied[name] = v
		}
		switch importPath {
		case "net/http":
			for _, name := range deniedHTTPNames {
				delete(copied, name)
			}
		case "os":
			for name := range copied {
				if !contains(allowedOSNames, name) {
					delete(copied, name)
				}
			}
		}
		out[key] = copied
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// checkImport says why an import path is refused, or "" when it is allowed. Paths whose first
// element has a dot are the plugin's own and vendored packages: the interpreter finds them in
// the plugin directory or not at all, and their imports are checked like the plugin's.
func checkImport(importPath string) string {
	switch {
	case importPath == reservedImport:
		return "is reserved by the host"
	case strings.HasPrefix(importPath, "."):
		return "is a relative import; vendor the package and import it by its path"
	}
	if reason, ok := forbiddenReasons[importPath]; ok {
		return "is refused: it gives " + reason
	}
	first, _, _ := strings.Cut(importPath, "/")
	if strings.Contains(first, ".") {
		return ""
	}
	if contains(allowedPackages, importPath) {
		return ""
	}
	return "is not on the host's standard library allowlist"
}

// refusedImports checks every import of the plugin and its vendored packages.
func refusedImports(imports map[string][]string) error {
	var problems []string
	paths := make([]string, 0, len(imports))
	for p := range imports {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if reason := checkImport(p); reason != "" {
			problems = append(problems, fmt.Sprintf("import %q %s (in %s)", p, reason, strings.Join(imports[p], ", ")))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the plugin is refused: %s", strings.Join(problems, "; "))
	}
	return nil
}
