package main

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/traefik/yaegi/interp"
)

// instance is one interpreter with one plugin loaded in it: the plugin of one tenant and one
// config. Interpreters are never shared across tenants.
type instance struct {
	interp       *interp.Interpreter
	run          *interp.Program
	createConfig reflect.Value
	newFn        reflect.Value
	handler      http.Handler

	// turn admits one call at a time. An interpreter is cancelled as a whole, so two calls on
	// one cannot have their own deadlines.
	turn        chan struct{}
	pending     func()
	current     atomic.Pointer[exchange]
	warnWrapped sync.Once
	// dead is set when a deadline stopped the interpreter: it cannot run plugin code again, so a
	// call that waited for its turn must not run on it (the handler would return at once, and
	// its silence would read as "respond 200").
	dead atomic.Bool
}

// newInstance loads the plugin's package into a fresh interpreter that can import only the
// allowed packages, and finds CreateConfig and New. It runs none of the plugin's functions.
func newInstance(source *Source) (*instance, error) {
	in := &instance{turn: make(chan struct{}, 1)}
	in.interp = interp.New(interp.Options{
		GoPath:               goPath,
		SourcecodeFilesystem: source.FS,
		// The interpreter adds Stdin, Args and Environ to the os package itself: an empty
		// environment, a one word command line, and a Stdin that is not a file, which it then
		// leaves out (Stdout and Stderr stay the host's, so plugin logs reach podgate's log).
		Env:   []string{},
		Args:  []string{"yaegi-plugin"},
		Stdin: strings.NewReader(""),
	})
	if err := in.interp.Use(exports()); err != nil {
		return nil, fmt.Errorf("registering the allowed packages: %w", err)
	}
	err := in.interp.Use(interp.Exports{
		reservedImport + "/hostcall": {"Run": reflect.ValueOf(func() { in.pending() })},
	})
	if err != nil {
		return nil, err
	}
	// Imports and the plugin's package-level code run here; a plugin whose init loops stops
	// the load at the build timeout instead of hanging the host.
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	for _, src := range []string{
		fmt.Sprintf("import hostcall %q", reservedImport),
		fmt.Sprintf("import plugin %q", source.Import),
	} {
		if _, err := in.interp.EvalWithContext(ctx, src); err != nil {
			return nil, fmt.Errorf("loading %s: %w", source.Import, err)
		}
	}
	if in.run, err = in.interp.Compile("hostcall.Run()"); err != nil {
		return nil, err
	}
	if in.createConfig, err = in.interp.Eval("plugin.CreateConfig"); err != nil {
		return nil, fmt.Errorf("the plugin has no CreateConfig: %w", err)
	}
	if in.newFn, err = in.interp.Eval("plugin.New"); err != nil {
		return nil, fmt.Errorf("the plugin has no New: %w", err)
	}
	if t := in.createConfig.Type(); t.Kind() != reflect.Func || t.NumIn() != 0 || t.NumOut() != 1 || t.Out(0).Kind() != reflect.Ptr {
		return nil, fmt.Errorf("CreateConfig must be func() *Config, not %s", t)
	}
	handler := reflect.TypeOf((*http.Handler)(nil)).Elem()
	errType := reflect.TypeOf((*error)(nil)).Elem()
	if t := in.newFn.Type(); t.Kind() != reflect.Func || t.NumIn() != 4 || t.NumOut() != 2 ||
		t.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() || t.In(1) != handler ||
		t.In(3).Kind() != reflect.String || t.Out(0) != handler || t.Out(1) != errType {
		return nil, fmt.Errorf("New must be func(context.Context, http.Handler, *Config, string) (http.Handler, error), not %s", t)
	}
	return in, nil
}

// exec runs fn under the interpreter until it returns or ctx ends. When ctx ends first the
// interpreter stops running the plugin's code and the instance cannot run again.
func (in *instance) exec(ctx context.Context, fn func()) error {
	in.pending = fn
	_, err := in.interp.ExecuteWithContext(ctx, in.run)
	return err
}

// forward is the `next` handler given to the plugin's New.
func (in *instance) forward(w http.ResponseWriter, r *http.Request) {
	if ex := in.current.Load(); ex != nil {
		ex.forward(w, r)
	}
}
