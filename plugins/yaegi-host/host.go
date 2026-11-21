package main

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/traefik/yaegi/interp"
)

// maxInstances bounds the plugin instances one host keeps; the least recently used goes first.
const maxInstances = 64

// buildTimeout bounds creating an instance (CreateConfig, the config decoder and New). A new
// tenant or config pays for it on its first call, which may then fail its own deadline while the
// instance finishes; the next call finds it.
const buildTimeout = 10 * time.Second

// Host serves one Traefik plugin to podgate. It holds an instance of the plugin per tenant and
// config.
type Host struct {
	name   string
	source *Source

	mu      sync.Mutex
	order   *list.List // of *entry, most recently used first
	entries map[string]*entry
	max     int
}

// NewHost loads the plugin once to refuse it early: its imports are checked by LoadSource, and
// here it must also load under the interpreter and export CreateConfig and New.
func NewHost(name string, source *Source) (*Host, error) {
	h := &Host{
		name:    name,
		source:  source,
		order:   list.New(),
		entries: map[string]*entry{},
		max:     maxInstances,
	}
	if _, err := newInstance(source); err != nil {
		return nil, err
	}
	return h, nil
}

// entry is a cache slot. The instance is built once, outside the lock; callers of the same
// tenant and config wait on ready.
type entry struct {
	key   string
	elem  *list.Element
	ready chan struct{}
	inst  *instance
	err   *callError
}

func fingerprint(tenant string, config []byte) string {
	sum := sha256.Sum256(config)
	return fmt.Sprintf("%d:%s:%s", len(tenant), tenant, hex.EncodeToString(sum[:]))
}

// instanceFor returns the instance of tenant and config, building it when there is none.
func (h *Host) instanceFor(ctx context.Context, tenant string, config []byte) (*instance, *callError) {
	key := fingerprint(tenant, config)
	h.mu.Lock()
	e, ok := h.entries[key]
	if ok {
		h.order.MoveToFront(e.elem)
	} else {
		e = &entry{key: key, ready: make(chan struct{})}
		e.elem = h.order.PushFront(e)
		h.entries[key] = e
		for h.order.Len() > h.max {
			oldest := h.order.Back()
			h.drop(oldest.Value.(*entry))
		}
		go h.build(e, tenant, config)
	}
	h.mu.Unlock()
	select {
	case <-e.ready:
		return e.inst, e.err
	case <-ctx.Done():
		return nil, failf(codeDeadlineExceeded, "the plugin instance for this tenant and config is still loading")
	}
}

// drop removes e from the cache. Callers hold h.mu. A call still running on the instance
// finishes; the instance is closed when it has.
func (h *Host) drop(e *entry) {
	if h.entries[e.key] == e {
		delete(h.entries, e.key)
		h.order.Remove(e.elem)
	}
}

func (h *Host) build(e *entry, tenant string, config []byte) {
	started := time.Now()
	inst, err := h.createInstance(tenant, config)
	if err != nil {
		e.err = err
	} else {
		e.inst = inst
	}
	close(e.ready)
	if err != nil {
		log.Printf("tenant %q: the plugin could not be created: %v", tenant, err)
		return
	}
	log.Printf("tenant %q: created plugin instance %s in %s", tenant, e.key[len(e.key)-8:], time.Since(started).Round(time.Millisecond))
}

func (h *Host) createInstance(tenant string, config []byte) (*instance, *callError) {
	inst, err := newInstance(h.source)
	if err != nil {
		return nil, failf(codeInternal, "the plugin cannot be loaded: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	var failure *callError
	err = inst.exec(ctx, func() {
		cfg := inst.createConfig.Call(nil)[0]
		if cfg.IsNil() {
			failure = failf(codeInternal, "CreateConfig returned nil")
			return
		}
		if err := decodeConfig(cfg, config); err != nil {
			failure = failf(codeInvalidArgument, "%v", err)
			return
		}
		next := http.HandlerFunc(inst.forward)
		out := inst.newFn.Call([]reflect.Value{
			reflect.ValueOf(context.Background()),
			reflect.ValueOf(next),
			cfg,
			reflect.ValueOf(h.name),
		})
		if errv := out[1]; !errv.IsNil() {
			failure = failf(codeInvalidArgument, "New returned an error: %v", errv.Interface())
			return
		}
		handler, ok := out[0].Interface().(http.Handler)
		if !ok || out[0].IsNil() {
			failure = failf(codeInternal, "New returned no handler")
			return
		}
		inst.handler = handler
	})
	if err != nil {
		return nil, describe(err, "building the plugin")
	}
	if failure != nil {
		return nil, failure
	}
	return inst, nil
}

// describe turns what stopped an interpreted run into a failed call.
func describe(err error, doing string) *callError {
	var panicked interp.Panic
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return failf(codeDeadlineExceeded, "%s did not finish in time", doing)
	case errors.As(err, &panicked):
		return failf(codeInternal, "the plugin panicked while %s: %v", doing, panicked.Value)
	}
	return failf(codeInternal, "the plugin failed while %s: %v", doing, err)
}

// Process decides one request_headers call.
func (h *Host) Process(ctx context.Context, c *Call) (*Decision, *callError) {
	if c.Phase != PhaseRequestHeaders {
		return nil, failf(codeUnimplemented, "the phase %d is not served: a Traefik plugin only sees request headers", c.Phase)
	}
	inst, cerr := h.instanceFor(ctx, c.Tenant, c.Config)
	if cerr != nil {
		return nil, cerr
	}
	select {
	case inst.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, failf(codeDeadlineExceeded, "the plugin is busy with another call of this tenant")
	}
	defer func() { <-inst.turn }()
	if inst.dead.Load() {
		return nil, failf(codeUnavailable, "the plugin instance was stopped by an earlier call that passed its deadline")
	}
	ex, cerr := newExchange(ctx, c)
	if cerr != nil {
		return nil, cerr
	}
	inst.current.Store(ex)
	err := inst.exec(ctx, func() { inst.handler.ServeHTTP(ex.rec, ex.req) })
	inst.current.Store(nil)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			// The interpreter stops the run, but the instance cannot run again.
			inst.dead.Store(true)
			h.evict(c.Tenant, c.Config, inst)
		}
		return nil, describe(err, "handling the request")
	}
	if ex.foreign {
		inst.warnWrapped.Do(func() {
			log.Printf("the plugin passes its own ResponseWriter to next; changes it makes to the upstream response have no effect here")
		})
	}
	return ex.decision()
}

// evict removes the instance of tenant and config if it is still inst.
func (h *Host) evict(tenant string, config []byte, inst *instance) {
	key := fingerprint(tenant, config)
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.entries[key]; e != nil && e.inst == inst {
		h.drop(e)
	}
}

// Instances reports how many instances the host holds, for tests.
func (h *Host) Instances() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.order.Len()
}
