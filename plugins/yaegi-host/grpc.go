package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The gRPC the protocol needs, on net/http: two unary calls over HTTP/2 without TLS on a unix
// socket, from one client (podgate), no compression and no streaming. A gRPC library would add
// a few dozen modules for it. Messages are framed with the 5-byte prefix of the gRPC
// specification; the status goes in the trailers, or in the headers when there is no message.

const (
	describePath = "/podgate.plugin.v1.Plugin/Describe"
	processPath  = "/podgate.plugin.v1.Plugin/Process"

	// maxCall is the largest call podgate sends (docs/ref/mw-plugin.md, Bounds).
	maxCall = 256 << 10

	defaultTimeout = 5 * time.Second
	maxTimeout     = 30 * time.Second
)

// grpcServer answers the Plugin service with a Host.
type grpcServer struct {
	host *Host
	name string
}

func (s *grpcServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("internal error: %v", p)
			grpcError(w, codeInternal, "internal error")
		}
	}()
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		grpcError(w, codeInvalidArgument, "not a gRPC call")
		return
	}
	if enc := r.Header.Get("Grpc-Encoding"); enc != "" && enc != "identity" {
		grpcError(w, codeUnimplemented, "compressed messages are not supported")
		return
	}
	if r.URL.Path != describePath && r.URL.Path != processPath {
		grpcError(w, codeUnimplemented, "unknown method "+r.URL.Path)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCall+5))
	if err != nil {
		grpcError(w, 8, "the call is larger than 256 KiB")
		return
	}
	message, cerr := unframe(body)
	if cerr != nil {
		grpcError(w, cerr.code, cerr.message)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout(r.Header.Get("Grpc-Timeout")))
	defer cancel()
	if r.URL.Path == describePath {
		d := &DescribeResponse{Name: s.name, ProtocolVersion: protocolVersion, Phases: []Phase{PhaseRequestHeaders}}
		grpcReply(w, d.Encode())
		return
	}
	call, err := DecodeCall(message)
	if err != nil {
		grpcError(w, codeInvalidArgument, err.Error())
		return
	}
	decision, cerr := s.host.Process(ctx, call)
	if cerr == nil {
		encoded := decision.Encode()
		if len(encoded) > maxDecision {
			cerr = failf(codeFailedPrecondition, "the decision is %d bytes; the limit is %d", len(encoded), maxDecision)
		} else {
			grpcReply(w, encoded)
			return
		}
	}
	log.Printf("call failed (tenant %q, middleware %q): %s", call.Tenant, call.Middleware, cerr.message)
	grpcError(w, cerr.code, cerr.message)
}

// unframe returns the one message of a request body.
func unframe(body []byte) ([]byte, *callError) {
	if len(body) < 5 {
		return nil, failf(codeInvalidArgument, "the body has no message prefix")
	}
	if body[0] != 0 {
		return nil, failf(codeUnimplemented, "compressed messages are not supported")
	}
	n := int(body[1])<<24 | int(body[2])<<16 | int(body[3])<<8 | int(body[4])
	if n != len(body)-5 {
		return nil, failf(codeInvalidArgument, "the message prefix says %d bytes, the body has %d", n, len(body)-5)
	}
	return body[5:], nil
}

// timeout parses the grpc-timeout header: up to 8 digits and a unit.
func timeout(header string) time.Duration {
	if len(header) < 2 || len(header) > 9 {
		return defaultTimeout
	}
	n, err := strconv.ParseUint(header[:len(header)-1], 10, 32)
	if err != nil {
		return defaultTimeout
	}
	unit := map[byte]time.Duration{
		'H': time.Hour, 'M': time.Minute, 'S': time.Second,
		'm': time.Millisecond, 'u': time.Microsecond, 'n': time.Nanosecond,
	}[header[len(header)-1]]
	if unit == 0 {
		return defaultTimeout
	}
	return min(time.Duration(n)*unit, maxTimeout)
}

func grpcReply(w http.ResponseWriter, message []byte) {
	w.Header().Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	framed := make([]byte, 5, 5+len(message))
	framed[1], framed[2], framed[3], framed[4] = byte(len(message)>>24), byte(len(message)>>16), byte(len(message)>>8), byte(len(message))
	if _, err := w.Write(append(framed, message...)); err != nil {
		return
	}
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
}

// grpcError answers a status with no message, in the headers: a trailers-only response.
func grpcError(w http.ResponseWriter, code int, message string) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Grpc-Status", strconv.Itoa(code))
	h.Set("Grpc-Message", percentEncode(message))
	w.WriteHeader(http.StatusOK)
}

// percentEncode is the grpc-message encoding: bytes outside printable ASCII, and '%', as %XX.
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
