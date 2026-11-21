package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// maxDecision is the limit of the protocol on one decision (docs/ref/mw-plugin.md, Bounds).
const maxDecision = 64 << 10

// Why a call fails. The code is the gRPC status the host answers; podgate treats every one of
// them as a failed call and applies the middleware's on_plugin_error.
type callError struct {
	code    int
	message string
}

func (e *callError) Error() string { return e.message }

const (
	codeInvalidArgument    = 3
	codeDeadlineExceeded   = 4
	codeFailedPrecondition = 9
	codeUnimplemented      = 12
	codeUnavailable        = 14
	codeInternal           = 13
)

func failf(code int, format string, args ...any) *callError {
	return &callError{code: code, message: fmt.Sprintf(format, args...)}
}

// unsupported is the failure of a plugin that did something the protocol cannot carry. It is
// a failed call so the change is never dropped silently.
func unsupported(format string, args ...any) *callError {
	return failf(codeFailedPrecondition, "plugin_unsupported_mutation: "+format, args...)
}

// guardBody is the request body a plugin sees: empty, because a request_headers call carries no
// body. A plugin that reads it would decide on a body it never saw.
type guardBody struct{ read bool }

func (b *guardBody) Read([]byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func (b *guardBody) Close() error { return nil }

// recorder is the ResponseWriter a plugin writes to. Nothing goes anywhere until the host
// turns it into a decision.
type recorder struct {
	header      http.Header
	status      int
	wroteHeader bool
	body        []byte
	overflow    bool
}

func newRecorder() *recorder { return &recorder{header: http.Header{}} }

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = status
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if len(r.body)+len(p) > maxDecision {
		r.overflow = true
		return 0, errors.New("the response is larger than a plugin decision may be")
	}
	r.body = append(r.body, p...)
	return len(p), nil
}

// exchange is one call from the request built for the plugin to the decision.
type exchange struct {
	req    *http.Request
	url    string
	method string
	host   string
	before map[string][]string
	guard  *guardBody
	rec    *recorder

	forwarded *http.Request
	nexts     int
	foreign   bool
}

// newExchange builds the request of a request_headers call as a Traefik plugin sees it from
// Traefik: a server request, with the target as URL and RequestURI, no body, and the headers
// the middleware sent.
func newExchange(ctx context.Context, c *Call) (*exchange, *callError) {
	target := c.Target
	if target == "" {
		target = "/"
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, failf(codeInvalidArgument, "the request target %q is not valid: %v", target, err)
	}
	guard := &guardBody{}
	req := &http.Request{
		Method:     c.Method,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       guard,
		Host:       c.Host,
		RequestURI: target,
	}
	req = req.WithContext(ctx)
	for _, h := range c.Headers {
		req.Header.Add(h.Name, string(h.Value))
	}
	if n, err := strconv.ParseInt(req.Header.Get("Content-Length"), 10, 64); err == nil && n >= 0 {
		req.ContentLength = n
	}
	if ip := c.ClientAddr; ip != "" {
		req.RemoteAddr = net.JoinHostPort(ip, "0")
	}
	if c.Scheme == "https" {
		req.TLS = &tls.ConnectionState{HandshakeComplete: true}
	}
	return &exchange{
		req:    req,
		url:    u.String(),
		method: c.Method,
		host:   c.Host,
		before: lowered(req.Header),
		guard:  guard,
		rec:    newRecorder(),
	}, nil
}

// lowered is the headers by lower case name, values in order, as a copy.
func lowered(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := strings.ToLower(k)
		out[name] = append(out[name], h[k]...)
	}
	return out
}

// forward is what the `next` handler of the plugin does: note that the request goes on, and with
// which request and writer.
func (ex *exchange) forward(w http.ResponseWriter, r *http.Request) {
	ex.nexts++
	if ex.nexts > 1 {
		return
	}
	ex.forwarded = r
	if rec, ok := w.(*recorder); !ok || rec != ex.rec {
		ex.foreign = true
	}
}

// editable mirrors the rule of the protocol: a plugin cannot touch a header that frames the
// message or belongs to the connection.
func editable(name string) error {
	switch name {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade",
		"te", "trailer", "http2-settings":
		return fmt.Errorf("the header %s frames the message or belongs to the connection", name)
	}
	if strings.HasPrefix(name, "proxy-") {
		return fmt.Errorf("the header %s belongs to a proxy hop", name)
	}
	return nil
}

// decision turns what the handler did into the answer of the call.
func (ex *exchange) decision() (*Decision, *callError) {
	if ex.nexts == 0 {
		return ex.respond()
	}
	if ex.nexts > 1 {
		return nil, unsupported("the handler called next %d times", ex.nexts)
	}
	if ex.rec.wroteHeader {
		return nil, unsupported("the handler wrote a response and also called next")
	}
	fr := ex.forwarded
	switch {
	case fr == nil:
		return nil, failf(codeInternal, "the handler passed a nil request to next")
	case fr.Method != ex.method:
		return nil, unsupported("the method was changed to %q", fr.Method)
	case fr.Host != ex.host:
		return nil, unsupported("the host was changed (req.Host)")
	case fr.URL == nil || fr.URL.String() != ex.url:
		return nil, unsupported("the URL path or query was changed (req.URL)")
	case fr.Body != io.ReadCloser(ex.guard) || ex.guard.read:
		return nil, unsupported("the request body was read or replaced (req.Body)")
	}
	d := &Decision{Action: ActionContinue}
	if err := diffHeaders(d, ex.before, lowered(fr.Header)); err != nil {
		return nil, err
	}
	for name, values := range lowered(ex.rec.header) {
		if err := editable(name); err != nil {
			return nil, unsupported("%v", err)
		}
		for _, v := range values {
			d.AddResponseHeaders = append(d.AddResponseHeaders, Header{Name: name, Value: []byte(v)})
		}
	}
	sort.Slice(d.AddResponseHeaders, func(i, j int) bool { return d.AddResponseHeaders[i].Name < d.AddResponseHeaders[j].Name })
	return d, nil
}

// diffHeaders states the change from before to after as removals and replacements, the only
// edits of a request header the protocol has. A header with several values after the change
// cannot be replaced by one field, so it is refused.
func diffHeaders(d *Decision, before, after map[string][]string) *callError {
	names := make([]string, 0, len(after)+len(before))
	for name := range after {
		names = append(names, name)
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		was, now := before[name], after[name]
		if equal(was, now) {
			continue
		}
		if err := editable(name); err != nil {
			return unsupported("%v", err)
		}
		switch len(now) {
		case 0:
			d.RemoveRequestHeaders = append(d.RemoveRequestHeaders, name)
		case 1:
			d.SetRequestHeaders = append(d.SetRequestHeaders, Header{Name: name, Value: []byte(now[0])})
		default:
			return unsupported("the header %s was left with %d values; the protocol replaces a header by one value", name, len(now))
		}
	}
	return nil
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// respond is the decision of a handler that did not call next: the response it wrote.
func (ex *exchange) respond() (*Decision, *callError) {
	rec := ex.rec
	if rec.overflow {
		return nil, failf(codeFailedPrecondition, "the response is larger than the %d bytes of a decision", maxDecision)
	}
	status := rec.status
	if !rec.wroteHeader {
		status = http.StatusOK
	}
	if status < 200 || status > 599 {
		return nil, failf(codeFailedPrecondition, "the status %d is not 200 to 599", status)
	}
	response := &Response{Status: uint32(status), Body: rec.body}
	headers := lowered(rec.header)
	if len(rec.body) > 0 {
		if _, ok := headers["content-type"]; !ok {
			headers["content-type"] = []string{http.DetectContentType(rec.body)}
		}
	}
	// A matching Content-Length is harmless and common; podgate frames the message itself.
	if v, ok := headers["content-length"]; ok {
		if len(v) != 1 || v[0] != strconv.Itoa(len(rec.body)) {
			return nil, unsupported("the header content-length does not match the body; podgate sets it")
		}
		delete(headers, "content-length")
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := editable(name); err != nil {
			return nil, unsupported("%v", err)
		}
		for _, v := range headers[name] {
			response.Headers = append(response.Headers, Header{Name: name, Value: []byte(v)})
		}
	}
	return &Decision{Action: ActionRespond, Response: response}, nil
}
