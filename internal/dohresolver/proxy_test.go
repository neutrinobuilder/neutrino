// Copyright (C) 2026 Neutrino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dohresolver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startEchoServer starts a local TCP server that echoes back every byte it
// receives, the simulated "upstream" of the CONNECT tunnel, keeping the
// whole test local and deterministic (no real DoH query: the CONNECT host is
// always a literal IP, so Lookup resolves it without network access).
func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestProxyAddrFormat(t *testing.T) {
	p, err := StartProxy()
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer p.Close()

	host, port, err := net.SplitHostPort(p.Addr())
	if err != nil {
		t.Fatalf("Addr() = %q, not a valid host:port: %v", p.Addr(), err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("Addr() host = %q, want 127.0.0.1", host)
	}
	if port == "" || port == "0" {
		t.Fatalf("Addr() port = %q, want an assigned port", port)
	}
}

func TestProxyConnectTunnelsData(t *testing.T) {
	upstream := startEchoServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstream.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	p, err := StartProxy()
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n", upstreamPort, upstreamPort)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("Write CONNECT: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the status line: %v", err)
	}
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("status line = %q, want 200 Connection Established", status)
	}
	// Consume the empty line that closes the response headers.
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("reading the empty line: %v", err)
	}

	const payload = "hello through the tunnel"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("Write payload: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echoed); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	if string(echoed) != payload {
		t.Fatalf("eco = %q, want %q", echoed, payload)
	}
}

func TestProxyRejectsMalformedRequest(t *testing.T) {
	p, err := StartProxy()
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the status line: %v", err)
	}
	if status != "HTTP/1.1 400 Bad Request\r\n" {
		t.Fatalf("status line = %q, want 400 Bad Request", status)
	}
}

func TestProxyRejectsBadHostPort(t *testing.T) {
	p, err := StartProxy()
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("CONNECT not-a-hostport HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the status line: %v", err)
	}
	if status != "HTTP/1.1 400 Bad Request\r\n" {
		t.Fatalf("status line = %q, want 400 Bad Request", status)
	}
}

func TestProxyBadGatewayOnUnreachableUpstream(t *testing.T) {
	p, err := StartProxy()
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer p.Close()

	// A port almost certainly unused on loopback: no listener there.
	conn, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the status line: %v", err)
	}
	if status != "HTTP/1.1 502 Bad Gateway\r\n" {
		t.Fatalf("status line = %q, want 502 Bad Gateway", status)
	}
}

func TestProxyCloseStopsAccepting(t *testing.T) {
	p, err := StartProxy()
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	addr := p.Addr()
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Give the accept loop time to exit after the listener is closed.
	time.Sleep(50 * time.Millisecond)
	if _, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		t.Fatal("Dial: want an error, the proxy should be closed")
	}
}

// TestProxyClosesConnectionOnSilentClient checks that a client which
// connects and never sends a complete CONNECT line still gets its connection
// closed within a bounded time (the 10s read deadline in handleConn) instead
// of blocking that goroutine indefinitely, the 2048-byte cap alone limits
// only how much is read, not how long it may take. Slow by construction
// (waits for the real deadline).
func TestProxyClosesConnectionOnSilentClient(t *testing.T) {
	p, err := StartProxy()
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()

	// No write: the server waits in vain for a complete CONNECT line.
	conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	buf := make([]byte, 1)
	n, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatalf("Read: expected an error (connection closed by server), read %d bytes", n)
	}
	if readErr == io.EOF || strings.Contains(readErr.Error(), "reset") {
		return // expected: the server closed the connection after the deadline
	}
	t.Fatalf("Read: unexpected error (likely a TEST timeout, not the server's): %v", readErr)
}
