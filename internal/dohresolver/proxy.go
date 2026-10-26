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
	"context"
	"io"
	"net"
	"strings"
	"time"
)

// Proxy is a single-purpose local HTTP CONNECT proxy: it resolves the
// requested tunnel's host via Lookup (DoH, never the system resolver) and
// then forwards raw bytes without inspecting them — the TLS of the
// downstream connection (e.g. i2pd's HTTPS reseed) stays intact end-to-end,
// the proxy sees only an opaque TCP tunnel after the initial CONNECT.
type Proxy struct {
	ln net.Listener
}

// StartProxy opens a listener on 127.0.0.1 (a free port assigned by the
// system) and starts the accept loop in the background. Must be closed with
// Close.
func StartProxy() (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln}
	go p.acceptLoop()
	return p, nil
}

// Addr returns "127.0.0.1:PORT", to pass to --reseed.proxy=http://<Addr>.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

func (p *Proxy) Close() error { return p.ln.Close() }

func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed via Close, or a fatal error: both end the loop
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(client net.Conn) {
	defer client.Close()

	// Deadline only for reading the CONNECT line — the 2048-byte cap below
	// limits only how much is read, not how long it may take, so without
	// this a client that connects and never sends anything (or stalls
	// mid-line) would block this goroutine forever. Cleared immediately
	// after, before forwarding the actual tunnel below, which must be able
	// to stay open indefinitely.
	client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Reads only the first line of the CONNECT request (e.g. "CONNECT
	// host:443 HTTP/1.1") — no full HTTP parser is needed, the remaining
	// headers are unused by a single-purpose CONNECT proxy.
	buf := make([]byte, 0, 512)
	one := make([]byte, 1)
	for len(buf) < 2048 {
		n, err := client.Read(one)
		if n == 0 || err != nil {
			return
		}
		buf = append(buf, one[0])
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			break
		}
	}
	client.SetReadDeadline(time.Time{})
	line := strings.SplitN(string(buf), "\r\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
		client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	hostPort := fields[1]
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := Lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(ips[0].String(), port), 10*time.Second)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}
