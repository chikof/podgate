package main

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// The messages of proto/podgate_plugin.proto (package podgate.plugin.v1), encoded by hand with
// protowire: the protocol is five small messages, and a generator (protoc, or a Go parser of
// .proto files) would be a bigger dependency than the code it replaces. wire_test.go checks the
// field numbers below against the .proto file, so the two cannot drift apart unnoticed.

const protocolVersion = 1

// Phase is the enum `Phase` of the protocol.
type Phase int32

// The phases of the protocol.
const (
	PhaseUnspecified     Phase = 0
	PhaseRequestHeaders  Phase = 1
	PhaseRequestBody     Phase = 2
	PhaseResponseHeaders Phase = 3
)

// Action is the enum `Action` of the protocol.
type Action int32

// The actions of the protocol.
const (
	ActionContinue Action = 0
	ActionRespond  Action = 1
)

// Header is message `Header`: a lower case name and a raw value.
type Header struct {
	Name  string
	Value []byte
}

// Call is message `Call`.
type Call struct {
	Phase           Phase
	Tenant          string
	App             string
	Router          string
	Middleware      string
	Config          []byte
	ClientAddr      string
	Method          string
	Target          string
	Host            string
	Scheme          string
	Headers         []Header
	Body            []byte
	Status          uint32
	ResponseHeaders []Header
}

// Response is message `Response`.
type Response struct {
	Status  uint32
	Headers []Header
	Body    []byte
}

// Decision is message `Decision`.
type Decision struct {
	Action               Action
	SetRequestHeaders    []Header
	RemoveRequestHeaders []string
	AddResponseHeaders   []Header
	Response             *Response
}

// DescribeResponse is message `DescribeResponse`.
type DescribeResponse struct {
	Name            string
	ProtocolVersion uint32
	Phases          []Phase
}

// Field numbers. Keyed by "Message.field"; wire_test.go compares this table with the .proto.
var fieldNumbers = map[string]protowire.Number{
	"DescribeResponse.name":             1,
	"DescribeResponse.protocol_version": 2,
	"DescribeResponse.phases":           3,
	"Header.name":                       1,
	"Header.value":                      2,
	"Call.phase":                        1,
	"Call.tenant":                       2,
	"Call.app":                          3,
	"Call.router":                       4,
	"Call.middleware":                   5,
	"Call.config":                       6,
	"Call.client_addr":                  7,
	"Call.method":                       8,
	"Call.target":                       9,
	"Call.host":                         10,
	"Call.scheme":                       11,
	"Call.headers":                      12,
	"Call.body":                         13,
	"Call.status":                       14,
	"Call.response_headers":             15,
	"Decision.action":                   1,
	"Decision.set_request_headers":      2,
	"Decision.remove_request_headers":   3,
	"Decision.add_response_headers":     4,
	"Decision.response":                 5,
	"Response.status":                   1,
	"Response.headers":                  2,
	"Response.body":                     3,
}

var errMalformed = errors.New("malformed protobuf message")

// walk calls visit for every field of message b. visit ignores a field it does not know, which is
// skipped, as protobuf requires.
func walk(b []byte, visit func(num protowire.Number, typ protowire.Type, v []byte) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fmt.Errorf("%w: %w", errMalformed, protowire.ParseError(n))
		}
		b = b[n:]
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return fmt.Errorf("%w: %w", errMalformed, protowire.ParseError(n))
		}
		if err := visit(num, typ, b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func varint(typ protowire.Type, v []byte) (uint64, error) {
	if typ != protowire.VarintType {
		return 0, errMalformed
	}
	x, n := protowire.ConsumeVarint(v)
	if n < 0 {
		return 0, errMalformed
	}
	return x, nil
}

func bytesOf(typ protowire.Type, v []byte) ([]byte, error) {
	if typ != protowire.BytesType {
		return nil, errMalformed
	}
	x, n := protowire.ConsumeBytes(v)
	if n < 0 {
		return nil, errMalformed
	}
	return x, nil
}

func decodeHeader(b []byte) (Header, error) {
	var h Header
	err := walk(b, func(num protowire.Number, typ protowire.Type, v []byte) error {
		switch num {
		case fieldNumbers["Header.name"]:
			x, err := bytesOf(typ, v)
			h.Name = string(x)
			return err
		case fieldNumbers["Header.value"]:
			x, err := bytesOf(typ, v)
			h.Value = append([]byte(nil), x...)
			return err
		}
		return nil
	})
	return h, err
}

// DecodeCall parses a `Call`.
func DecodeCall(b []byte) (*Call, error) {
	c := &Call{}
	err := walk(b, func(num protowire.Number, typ protowire.Type, v []byte) error {
		str := func(dst *string) error {
			x, err := bytesOf(typ, v)
			*dst = string(x)
			return err
		}
		raw := func(dst *[]byte) error {
			x, err := bytesOf(typ, v)
			*dst = append([]byte(nil), x...)
			return err
		}
		header := func(dst *[]Header) error {
			x, err := bytesOf(typ, v)
			if err != nil {
				return err
			}
			h, err := decodeHeader(x)
			*dst = append(*dst, h)
			return err
		}
		switch num {
		case fieldNumbers["Call.phase"]:
			x, err := varint(typ, v)
			c.Phase = Phase(int32(x))
			return err
		case fieldNumbers["Call.tenant"]:
			return str(&c.Tenant)
		case fieldNumbers["Call.app"]:
			return str(&c.App)
		case fieldNumbers["Call.router"]:
			return str(&c.Router)
		case fieldNumbers["Call.middleware"]:
			return str(&c.Middleware)
		case fieldNumbers["Call.config"]:
			return raw(&c.Config)
		case fieldNumbers["Call.client_addr"]:
			return str(&c.ClientAddr)
		case fieldNumbers["Call.method"]:
			return str(&c.Method)
		case fieldNumbers["Call.target"]:
			return str(&c.Target)
		case fieldNumbers["Call.host"]:
			return str(&c.Host)
		case fieldNumbers["Call.scheme"]:
			return str(&c.Scheme)
		case fieldNumbers["Call.headers"]:
			return header(&c.Headers)
		case fieldNumbers["Call.body"]:
			return raw(&c.Body)
		case fieldNumbers["Call.status"]:
			x, err := varint(typ, v)
			c.Status = uint32(x)
			return err
		case fieldNumbers["Call.response_headers"]:
			return header(&c.ResponseHeaders)
		}
		return nil
	})
	return c, err
}

func appendHeaders(b []byte, num protowire.Number, headers []Header) []byte {
	for _, h := range headers {
		var m []byte
		m = protowire.AppendTag(m, fieldNumbers["Header.name"], protowire.BytesType)
		m = protowire.AppendString(m, h.Name)
		m = protowire.AppendTag(m, fieldNumbers["Header.value"], protowire.BytesType)
		m = protowire.AppendBytes(m, h.Value)
		b = protowire.AppendTag(b, num, protowire.BytesType)
		b = protowire.AppendBytes(b, m)
	}
	return b
}

// Encode serializes the decision.
func (d *Decision) Encode() []byte {
	var b []byte
	if d.Action != ActionContinue {
		b = protowire.AppendTag(b, fieldNumbers["Decision.action"], protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(d.Action))
	}
	b = appendHeaders(b, fieldNumbers["Decision.set_request_headers"], d.SetRequestHeaders)
	for _, name := range d.RemoveRequestHeaders {
		b = protowire.AppendTag(b, fieldNumbers["Decision.remove_request_headers"], protowire.BytesType)
		b = protowire.AppendString(b, name)
	}
	b = appendHeaders(b, fieldNumbers["Decision.add_response_headers"], d.AddResponseHeaders)
	if r := d.Response; r != nil {
		var m []byte
		m = protowire.AppendTag(m, fieldNumbers["Response.status"], protowire.VarintType)
		m = protowire.AppendVarint(m, uint64(r.Status))
		m = appendHeaders(m, fieldNumbers["Response.headers"], r.Headers)
		if len(r.Body) > 0 {
			m = protowire.AppendTag(m, fieldNumbers["Response.body"], protowire.BytesType)
			m = protowire.AppendBytes(m, r.Body)
		}
		b = protowire.AppendTag(b, fieldNumbers["Decision.response"], protowire.BytesType)
		b = protowire.AppendBytes(b, m)
	}
	return b
}

// Encode serializes the description.
func (d *DescribeResponse) Encode() []byte {
	var b []byte
	b = protowire.AppendTag(b, fieldNumbers["DescribeResponse.name"], protowire.BytesType)
	b = protowire.AppendString(b, d.Name)
	b = protowire.AppendTag(b, fieldNumbers["DescribeResponse.protocol_version"], protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(d.ProtocolVersion))
	var packed []byte
	for _, p := range d.Phases {
		packed = protowire.AppendVarint(packed, uint64(p))
	}
	b = protowire.AppendTag(b, fieldNumbers["DescribeResponse.phases"], protowire.BytesType)
	return protowire.AppendBytes(b, packed)
}
