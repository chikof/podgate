package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newTestHost(t *testing.T, dir string) *Host {
	t.Helper()
	source, err := LoadSource(filepath.Join("testdata", dir))
	if err != nil {
		t.Fatalf("LoadSource(%s): %v", dir, err)
	}
	host, err := NewHost(dir, source)
	if err != nil {
		t.Fatalf("NewHost(%s): %v", dir, err)
	}
	return host
}

type request struct {
	tenant  string
	config  string
	method  string
	target  string
	headers [][2]string
	timeout time.Duration
}

func (r request) call() *Call {
	c := &Call{
		Phase:      PhaseRequestHeaders,
		Tenant:     r.tenant,
		App:        "app",
		Router:     "router",
		Middleware: "mw",
		Config:     []byte(r.config),
		ClientAddr: "192.0.2.7",
		Method:     orDefault(r.method, "GET"),
		Target:     orDefault(r.target, "/path?q=1"),
		Host:       "a.test",
		Scheme:     "https",
	}
	for _, h := range r.headers {
		c.Headers = append(c.Headers, Header{Name: h[0], Value: []byte(h[1])})
	}
	return c
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func process(h *Host, r request) (*Decision, *callError) {
	timeout := r.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return h.Process(ctx, r.call())
}

func mustProcess(t *testing.T, h *Host, r request) *Decision {
	t.Helper()
	d, err := process(h, r)
	if err != nil {
		t.Fatalf("call failed: %s", err.message)
	}
	return d
}

func setOf(d *Decision) map[string]string {
	out := map[string]string{}
	for _, h := range d.SetRequestHeaders {
		out[h.Name] = string(h.Value)
	}
	return out
}

func TestHeaderAdderContinuesWithDiff(t *testing.T) {
	h := newTestHost(t, "headeradder")
	d := mustProcess(t, h, request{tenant: "t1", config: `{"header":"x-hello","value":"world"}`, headers: [][2]string{{"x-keep", "k"}}})
	if d.Action != ActionContinue {
		t.Fatalf("action %d", d.Action)
	}
	set := setOf(d)
	if set["x-hello"] != "world" || set["x-served"] != "1" || set["x-instance"] == "" {
		t.Fatalf("set = %v", set)
	}
	if _, kept := set["x-keep"]; kept || len(d.RemoveRequestHeaders) != 0 {
		t.Fatalf("an untouched header is in the diff: %+v", d)
	}
	if len(d.AddResponseHeaders) != 1 || d.AddResponseHeaders[0].Name != "x-plugin-name" || string(d.AddResponseHeaders[0].Value) != "headeradder" {
		t.Fatalf("response headers = %+v", d.AddResponseHeaders)
	}
}

func TestBlockerResponds(t *testing.T) {
	h := newTestHost(t, "blocker")
	d := mustProcess(t, h, request{tenant: "t1", config: `{"status":451}`, headers: [][2]string{{"x-block", "1"}}})
	if d.Action != ActionRespond || d.Response == nil || d.Response.Status != 451 || string(d.Response.Body) != "blocked by plugin\n" {
		t.Fatalf("decision = %+v", d)
	}
	var got []string
	for _, h := range d.Response.Headers {
		got = append(got, h.Name+"="+string(h.Value))
	}
	if strings.Join(got, ",") != "content-type=text/plain,x-blocked-by=blocker" {
		t.Fatalf("headers = %v", got)
	}
	pass := mustProcess(t, h, request{tenant: "t1", config: `{}`})
	if pass.Action != ActionContinue || len(pass.SetRequestHeaders) != 0 {
		t.Fatalf("a request without the header was not let through: %+v", pass)
	}
}

func TestConfigDecoded(t *testing.T) {
	h := newTestHost(t, "configcheck")
	config := `{"NAME":"n","count":3,"enabled":true,"tags":["a","b"],"labels":{"k":"v"},"nested":{"depth":2,"label":"x"},"ptr":{"depth":5,"Label":"p"},"plain":"pl"}`
	d := mustProcess(t, h, request{tenant: "t", config: config})
	want := "name=n count=3 enabled=true tags=a+b labels=1 nested=2/x ptr=5/p secret=kept plain=pl"
	if got := setOf(d)["x-cfg"]; got != want {
		t.Fatalf("x-cfg = %q, want %q", got, want)
	}
	d = mustProcess(t, h, request{tenant: "t", config: ``})
	if got := setOf(d)["x-cfg"]; !strings.HasPrefix(got, "name=default count=1 ") {
		t.Fatalf("an empty config must leave the defaults: %q", got)
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	h := newTestHost(t, "configcheck")
	for config, fragment := range map[string]string{
		`{"nme":"x"}`:                    `unknown config field "nme"`,
		`{"nested":{"depht":1}}`:         `unknown config field "depht" in nested`,
		`{"secret":"x"}`:                 `unknown config field "secret"`, // json:"-" is not settable
		`{"count":"three"}`:              `config field count`,
		`[1]`:                            `not a JSON object`,
		`{"tags":[1]}`:                   `config field tags`,
		`{"labels":{"a":1}}`:             `config field labels`,
		`{"nested":{"depth":1,"x":1}}`:   `unknown config field "x" in nested`,
		`{"ptr":{"depth":1,"zzz":true}}`: `unknown config field "zzz" in ptr`,
	} {
		_, err := process(h, request{tenant: "t", config: config})
		if err == nil || !strings.Contains(err.message, fragment) {
			t.Errorf("config %s: err = %v, want %q", config, err, fragment)
		}
	}
}

func TestNewErrorFailsTheCall(t *testing.T) {
	h := newTestHost(t, "headeradder")
	_, err := process(h, request{tenant: "t", config: `{"header":""}`})
	if err == nil || !strings.Contains(err.message, "header cannot be empty") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsupportedMutations(t *testing.T) {
	h := newTestHost(t, "mutator")
	for mode, fragment := range map[string]string{
		"path":            "URL path or query",
		"query":           "URL path or query",
		"host":            "host was changed",
		"method":          "method was changed",
		"body-replace":    "body was read or replaced",
		"body-read":       "body was read or replaced",
		"header-host":     "header host",
		"header-framing":  "header content-length",
		"multi-value":     "x-multi was left with 2 values",
		"clone":           "URL path or query",
		"write-then-next": "wrote a response and also called next",
		"twice":           "called next 2 times",
	} {
		_, err := process(h, request{tenant: "t", config: fmt.Sprintf(`{"mode":%q}`, mode)})
		if err == nil || !strings.HasPrefix(err.message, "plugin_unsupported_mutation: ") || !strings.Contains(err.message, fragment) {
			t.Errorf("mode %s: err = %v, want plugin_unsupported_mutation with %q", mode, err, fragment)
		}
	}
	for _, mode := range []string{"none", "wrap"} {
		d := mustProcess(t, h, request{tenant: "t", config: fmt.Sprintf(`{"mode":%q}`, mode)})
		if d.Action != ActionContinue || len(d.SetRequestHeaders) != 0 {
			t.Errorf("mode %s: decision = %+v", mode, d)
		}
	}
}

func TestPanicRecoveredAndLoopStopped(t *testing.T) {
	h := newTestHost(t, "chaos")
	_, err := process(h, request{tenant: "t", config: `{}`, headers: [][2]string{{"x-panic", "1"}}})
	if err == nil || !strings.Contains(err.message, "panicked") || !strings.Contains(err.message, "on purpose") {
		t.Fatalf("panic: err = %v", err)
	}
	started := time.Now()
	_, err = process(h, request{tenant: "t", config: `{}`, headers: [][2]string{{"x-loop", "1"}}, timeout: 300 * time.Millisecond})
	if err == nil || err.code != codeDeadlineExceeded {
		t.Fatalf("loop: err = %v", err)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("the loop was stopped after %s", took)
	}
	// The host serves on, with a fresh instance.
	d := mustProcess(t, h, request{tenant: "t", config: `{}`})
	if d.Action != ActionContinue {
		t.Fatalf("decision after the loop = %+v", d)
	}
}

func TestForbiddenImportsRefusedAtLoad(t *testing.T) {
	for dir, want := range map[string]string{
		"forbidden_unsafe":  `"unsafe" is refused: it gives unsafe memory access`,
		"forbidden_osexec":  `"os/exec" is refused: it gives starting processes`,
		"forbidden_net":     `"net" is refused: it gives network access`,
		"forbidden_syscall": `"syscall" is refused: it gives system calls`,
		"forbidden_reflect": `"reflect" is refused`,
		"forbidden_cgo":     `"C" is refused: it gives cgo (native code)`,
		"vendored_bad":      `"os/exec" is refused: it gives starting processes (in vendor/example.com/helper/exec/exec.go)`,
	} {
		_, err := LoadSource(filepath.Join("testdata", dir))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", dir, err, want)
		}
	}
}

func TestVendoredPackagesLoad(t *testing.T) {
	h := newTestHost(t, "vendored")
	d := mustProcess(t, h, request{tenant: "t", config: `{}`, headers: [][2]string{{"x-say", "hi"}}})
	if got := setOf(d)["x-shout"]; got != "HI!" {
		t.Fatalf("x-shout = %q", got)
	}
}

func TestCheckImport(t *testing.T) {
	for p, refused := range map[string]bool{
		"fmt": false, "net/http": false, "strings": false, "math/rand/v2": false, "github.com/acme/x": false,
		"os/exec": true, "unsafe": true, "net": true, "C": true, "crypto/tls": true, "io/fs": true,
		"database/sql": true, "plugin": true, "./local": true, "golang.org/x/net/http2": false,
		"not/listed": true, "podgate.invalid/hostcall": true, "text/template": true,
	} {
		if got := checkImport(p) != ""; got != refused {
			t.Errorf("checkImport(%q) refused = %v, want %v", p, got, refused)
		}
	}
}

func TestEveryAllowedPackageHasSymbols(t *testing.T) {
	symbols := exports()
	have := map[string]bool{}
	for key := range symbols {
		have[filepath.Dir(key)] = true
	}
	for _, p := range allowedPackages {
		if !have[p] {
			t.Errorf("allowed package %q has no symbols in this Yaegi version", p)
		}
	}
	for _, p := range []string{"net", "os/exec", "unsafe", "syscall", "crypto/tls", "reflect", "io/fs"} {
		if have[p] {
			t.Errorf("%q is exported to plugins", p)
		}
	}
	if _, ok := symbols["net/http/http"]["Get"]; ok {
		t.Error("http.Get is exported to plugins")
	}
	if _, ok := symbols["net/http/http"]["Header"]; !ok {
		t.Error("http.Header is not exported to plugins")
	}
	if _, ok := symbols["os/os"]["Exit"]; ok {
		t.Error("os.Exit is exported to plugins")
	}
}

func TestInstancesPerTenantAndConfig(t *testing.T) {
	h := newTestHost(t, "headeradder")
	id := func(tenant, config string) string {
		return setOf(mustProcess(t, h, request{tenant: tenant, config: config}))["x-instance"]
	}
	a1, a2 := id("t1", `{}`), id("t1", `{}`)
	other, changed := id("t2", `{}`), id("t1", `{"value":"x"}`)
	if a1 != a2 {
		t.Errorf("same tenant and config: instances %s and %s", a1, a2)
	}
	if a1 == other || a1 == changed || other == changed {
		t.Errorf("instances must differ by tenant and by config: %s %s %s", a1, other, changed)
	}
	if h.Instances() != 3 {
		t.Errorf("instances = %d, want 3", h.Instances())
	}
}

func TestInstanceCacheBounded(t *testing.T) {
	h := newTestHost(t, "headeradder")
	first := setOf(mustProcess(t, h, request{tenant: "t", config: `{"value":"0"}`}))["x-instance"]
	for i := 1; i <= maxInstances; i++ {
		mustProcess(t, h, request{tenant: "t", config: fmt.Sprintf(`{"value":"%d"}`, i)})
	}
	if h.Instances() != maxInstances {
		t.Fatalf("instances = %d, want %d", h.Instances(), maxInstances)
	}
	if again := setOf(mustProcess(t, h, request{tenant: "t", config: `{"value":"0"}`}))["x-instance"]; again == first {
		t.Fatalf("the least recently used instance was not evicted")
	}
	// The most recent one is still the same instance.
	last := fmt.Sprintf(`{"value":"%d"}`, maxInstances)
	a := setOf(mustProcess(t, h, request{tenant: "t", config: last}))["x-instance"]
	b := setOf(mustProcess(t, h, request{tenant: "t", config: last}))["x-instance"]
	if a != b {
		t.Fatalf("a recent instance was rebuilt")
	}
}

func TestOnlyRequestHeadersServed(t *testing.T) {
	h := newTestHost(t, "headeradder")
	c := request{tenant: "t"}.call()
	c.Phase = PhaseResponseHeaders
	_, err := h.Process(context.Background(), c)
	if err == nil || err.code != codeUnimplemented {
		t.Fatalf("err = %v", err)
	}
}

func cpuTime(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

// The interpreter must stop running a plugin's loop at the deadline, not only stop waiting for it.
func TestLoopStopsBurningCPU(t *testing.T) {
	h := newTestHost(t, "chaos")
	mustProcess(t, h, request{tenant: "t", config: `{}`}) // warm up: build the instance
	_, err := process(h, request{tenant: "t", config: `{}`, headers: [][2]string{{"x-loop", "1"}}, timeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("the loop was not stopped")
	}
	time.Sleep(300 * time.Millisecond)
	before := cpuTime(t)
	time.Sleep(500 * time.Millisecond)
	if burned := cpuTime(t) - before; burned > 150*time.Millisecond {
		t.Fatalf("the loop still burns CPU: %s in 500ms", burned)
	}
}

// A call that waited for its turn behind a call whose deadline stopped the interpreter must fail,
// not run on the stopped interpreter: the handler would return at once without calling next, which
// would read as an answer.
func TestCallQueuedBehindStoppedInstanceFails(t *testing.T) {
	h := newTestHost(t, "chaos")
	mustProcess(t, h, request{tenant: "t", config: `{}`}) // warm up: build the instance
	looping := make(chan *callError, 1)
	go func() {
		_, err := process(h, request{tenant: "t", config: `{}`, headers: [][2]string{{"x-loop", "1"}}, timeout: 300 * time.Millisecond})
		looping <- err
	}()
	time.Sleep(100 * time.Millisecond)
	d, err := process(h, request{tenant: "t", config: `{}`})
	if err == nil {
		t.Fatalf("a call queued behind a stopped instance was answered: %+v", d)
	}
	if err.code != codeUnavailable {
		t.Fatalf("err = %v", err)
	}
	if loop := <-looping; loop == nil || loop.code != codeDeadlineExceeded {
		t.Fatalf("the looping call: %v", loop)
	}
	if d := mustProcess(t, h, request{tenant: "t", config: `{}`}); d.Action != ActionContinue {
		t.Fatalf("decision on the fresh instance = %+v", d)
	}
}

func TestSandboxedSymbolsAreMissing(t *testing.T) {
	load := func(use string) error {
		src := "package plug\n\nimport (\n\t\"context\"\n\t\"net/http\"\n\t\"os\"\n)\n\nvar _ = " + use + "\n\n" +
			"type Config struct{}\n\nfunc CreateConfig() *Config { return &Config{} }\n\n" +
			"func New(ctx context.Context, next http.Handler, c *Config, n string) (http.Handler, error) { return next, nil }\n"
		dir := writePlugin(t, "type: middleware\nimport: github.com/acme/plug\n", map[string]string{"plug.go": src})
		source, err := LoadSource(dir)
		if err != nil {
			t.Fatalf("%s: %v", use, err)
		}
		_, err = NewHost("plug", source)
		return err
	}
	for _, ok := range []string{"os.Stdout", "os.Getenv", "os.Environ", "os.Args", "http.StatusOK", "http.NewRequest", "http.Header{}"} {
		if err := load(ok); err != nil {
			t.Errorf("%s must be available: %v", ok, err)
		}
	}
	for _, missing := range []string{
		"os.ReadFile", "os.Exit", "os.Open", "os.Stdin", "os.Getpid",
		"http.Get", "http.DefaultClient", "http.ListenAndServe", "http.FileServer", "http.Dir(\"/\")",
	} {
		err := load(missing)
		if err == nil || !strings.Contains(err.Error(), "undefined") {
			t.Errorf("%s: err = %v, want an undefined symbol", missing, err)
		}
	}
}
