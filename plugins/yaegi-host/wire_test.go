package main

import (
	"os"
	"regexp"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// protoFields reads "Message.field" to number from the protocol's .proto file.
func protoFields(t *testing.T) map[string]protowire.Number {
	t.Helper()
	text, err := os.ReadFile("../../proto/podgate_plugin.proto")
	if err != nil {
		t.Fatal(err)
	}
	message := regexp.MustCompile(`(?m)^message (\w+) \{`)
	field := regexp.MustCompile(`(?m)^\s+(?:repeated\s+)?[\w.]+\s+(\w+)\s*=\s*(\d+);`)
	out := map[string]protowire.Number{}
	starts := message.FindAllStringSubmatchIndex(string(text), -1)
	for i, s := range starts {
		end := len(text)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		name := string(text[s[2]:s[3]])
		for _, f := range field.FindAllStringSubmatch(string(text[s[1]:end]), -1) {
			var n int
			for _, c := range f[2] {
				n = n*10 + int(c-'0')
			}
			out[name+"."+f[1]] = protowire.Number(n)
		}
	}
	return out
}

func TestFieldNumbersMatchTheProto(t *testing.T) {
	proto := protoFields(t)
	if len(proto) == 0 {
		t.Fatal("no fields read from the .proto")
	}
	for name, n := range proto {
		if fieldNumbers[name] != n {
			t.Errorf("%s: the proto says %d, wire.go says %d", name, n, fieldNumbers[name])
		}
	}
	for name := range fieldNumbers {
		if _, ok := proto[name]; !ok {
			t.Errorf("%s is in wire.go but not in the .proto", name)
		}
	}
}

func TestDecodeCall(t *testing.T) {
	proto := protoFields(t)
	header := func(name, value string) []byte {
		var h []byte
		h = protowire.AppendTag(h, proto["Header.name"], protowire.BytesType)
		h = protowire.AppendString(h, name)
		h = protowire.AppendTag(h, proto["Header.value"], protowire.BytesType)
		return protowire.AppendString(h, value)
	}
	var b []byte
	b = protowire.AppendTag(b, proto["Call.phase"], protowire.VarintType)
	b = protowire.AppendVarint(b, 1)
	b = protowire.AppendTag(b, proto["Call.tenant"], protowire.BytesType)
	b = protowire.AppendString(b, "acme")
	b = protowire.AppendTag(b, proto["Call.config"], protowire.BytesType)
	b = protowire.AppendString(b, `{"a":1}`)
	b = protowire.AppendTag(b, proto["Call.target"], protowire.BytesType)
	b = protowire.AppendString(b, "/x?y=1")
	b = protowire.AppendTag(b, proto["Call.headers"], protowire.BytesType)
	b = protowire.AppendBytes(b, header("x-a", "1"))
	b = protowire.AppendTag(b, proto["Call.headers"], protowire.BytesType)
	b = protowire.AppendBytes(b, header("x-a", "2"))
	b = protowire.AppendTag(b, 99, protowire.VarintType) // an unknown field is skipped
	b = protowire.AppendVarint(b, 7)
	c, err := DecodeCall(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.Phase != PhaseRequestHeaders || c.Tenant != "acme" || string(c.Config) != `{"a":1}` || c.Target != "/x?y=1" ||
		len(c.Headers) != 2 || c.Headers[1].Name != "x-a" || string(c.Headers[1].Value) != "2" {
		t.Fatalf("call = %+v", c)
	}
	if _, err := DecodeCall(b[:len(b)-1]); err == nil {
		t.Fatal("a truncated message decoded")
	}
}

func TestEncodeDecision(t *testing.T) {
	d := &Decision{
		Action:               ActionRespond,
		Response:             &Response{Status: 403, Headers: []Header{{Name: "x-a", Value: []byte("1")}}, Body: []byte("no")},
		RemoveRequestHeaders: []string{"x-r"},
	}
	var seen = map[protowire.Number]int{}
	err := walk(d.Encode(), func(num protowire.Number, _ protowire.Type, _ []byte) error {
		seen[num]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	proto := protoFields(t)
	for _, name := range []string{"Decision.action", "Decision.remove_request_headers", "Decision.response"} {
		if seen[proto[name]] != 1 {
			t.Errorf("%s appears %d times", name, seen[proto[name]])
		}
	}
	if (&Decision{}).Encode() != nil {
		t.Error("the default decision must encode to nothing: a continue with no change")
	}
}
