package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// serve runs the host's gRPC server on a unix socket and returns an HTTP/2 client for it.
func serve(t *testing.T, dir string) *http.Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "p.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: &grpcServer{host: newTestHost(t, dir), name: dir}, Protocols: protocols}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	clientProtocols := new(http.Protocols)
	clientProtocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{
		Protocols: clientProtocols,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
}

func unary(t *testing.T, client *http.Client, method string, message []byte) (*http.Response, []byte) {
	t.Helper()
	framed := append([]byte{0, 0, 0, 0, byte(len(message))}, message...)
	req, err := http.NewRequest(http.MethodPost, "http://plugin"+method, bytes.NewReader(framed))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Grpc-Timeout", "5000m")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestGRPCDescribeAndProcess(t *testing.T) {
	client := serve(t, "headeradder")
	resp, body := unary(t, client, describePath, nil)
	if resp.ProtoMajor != 2 || resp.Trailer.Get("Grpc-Status") != "0" || len(body) < 5 {
		t.Fatalf("describe: proto %d, trailers %v, body %x", resp.ProtoMajor, resp.Trailer, body)
	}
	var name string
	var version, phases uint64
	err := walk(body[5:], func(num protowire.Number, typ protowire.Type, v []byte) error {
		switch num {
		case fieldNumbers["DescribeResponse.name"]:
			x, _ := bytesOf(typ, v)
			name = string(x)
		case fieldNumbers["DescribeResponse.protocol_version"]:
			version, _ = varint(typ, v)
		case fieldNumbers["DescribeResponse.phases"]:
			x, _ := bytesOf(typ, v)
			phases, _ = protowire.ConsumeVarint(x)
		}
		return nil
	})
	if err != nil || name != "headeradder" || version != 1 || Phase(phases) != PhaseRequestHeaders {
		t.Fatalf("describe = %q v%d phase %d (%v)", name, version, phases, err)
	}

	var call []byte
	call = protowire.AppendTag(call, fieldNumbers["Call.phase"], protowire.VarintType)
	call = protowire.AppendVarint(call, uint64(PhaseRequestHeaders))
	call = protowire.AppendTag(call, fieldNumbers["Call.method"], protowire.BytesType)
	call = protowire.AppendString(call, "GET")
	call = protowire.AppendTag(call, fieldNumbers["Call.target"], protowire.BytesType)
	call = protowire.AppendString(call, "/")
	resp, body = unary(t, client, processPath, call)
	if resp.Trailer.Get("Grpc-Status") != "0" || !bytes.Contains(body, []byte("x-example")) {
		t.Fatalf("process: trailers %v, body %q", resp.Trailer, body)
	}
}

func TestGRPCErrorsAreTrailersOnly(t *testing.T) {
	client := serve(t, "mutator")
	var call []byte
	call = protowire.AppendTag(call, fieldNumbers["Call.phase"], protowire.VarintType)
	call = protowire.AppendVarint(call, uint64(PhaseRequestHeaders))
	call = protowire.AppendTag(call, fieldNumbers["Call.config"], protowire.BytesType)
	call = protowire.AppendString(call, `{"mode":"path"}`)
	call = protowire.AppendTag(call, fieldNumbers["Call.target"], protowire.BytesType)
	call = protowire.AppendString(call, "/")
	resp, body := unary(t, client, processPath, call)
	if resp.Header.Get("Grpc-Status") != "9" || len(body) != 0 ||
		!bytes.Contains([]byte(resp.Header.Get("Grpc-Message")), []byte("plugin_unsupported_mutation")) {
		t.Fatalf("status %q message %q body %q", resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message"), body)
	}
	resp, _ = unary(t, client, "/podgate.plugin.v1.Plugin/Nope", nil)
	if resp.Header.Get("Grpc-Status") != "12" {
		t.Fatalf("unknown method: status %q", resp.Header.Get("Grpc-Status"))
	}
}
