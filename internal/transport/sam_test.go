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

package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSAMBridge simulates a minimal SAM v3 bridge on a local TCP
// listener: always replies HELLO with RESULT=OK, and for each following
// command returns the response given by handler (one per connection).
// Allows testing the whole sam.go protocol without a real i2pd.
type fakeSAMBridge struct {
	ln      net.Listener
	handler func(rw *bufio.ReadWriter, cmdLine string)
}

func startFakeSAMBridge(t *testing.T, handler func(rw *bufio.ReadWriter, cmdLine string)) *fakeSAMBridge {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	b := &fakeSAMBridge{ln: ln, handler: handler}
	go b.acceptLoop()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *fakeSAMBridge) acceptLoop() {
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handleConn(conn)
	}
}

func (b *fakeSAMBridge) handleConn(conn net.Conn) {
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	// HELLO
	helloLine, err := rw.ReadString('\n')
	if err != nil || !strings.HasPrefix(helloLine, "HELLO") {
		return
	}
	rw.WriteString("HELLO REPLY RESULT=OK VERSION=3.3\n")
	rw.Flush()

	// Next command (SESSION CREATE / STREAM ACCEPT / STREAM CONNECT), if
	// present — samHello alone (samDialRaw) sends no others.
	cmdLine, err := rw.ReadString('\n')
	if err != nil {
		return
	}
	if b.handler != nil {
		b.handler(rw, cmdLine)
	}
}

func (b *fakeSAMBridge) addr() string { return b.ln.Addr().String() }

func TestSamHelloSuccess(t *testing.T) {
	b := startFakeSAMBridge(t, nil)
	conn, err := net.Dial("tcp", b.addr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	if err := samHello(rw); err != nil {
		t.Fatalf("samHello: %v", err)
	}
}

func TestSamHelloFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		r.ReadString('\n')
		conn.Write([]byte("HELLO REPLY RESULT=NOVERSION\n"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	if err := samHello(rw); err == nil {
		t.Fatal("samHello: want an error for RESULT != OK")
	}
}

func TestSamDialRawSuccess(t *testing.T) {
	b := startFakeSAMBridge(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, rw, err := samDialRaw(ctx, b.addr())
	if err != nil {
		t.Fatalf("samDialRaw: %v", err)
	}
	defer conn.Close()
	if rw == nil {
		t.Fatal("samDialRaw: nil rw with nil err")
	}
}

func TestSamDialRawConnRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // nobody listening there now

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := samDialRaw(ctx, addr); err == nil {
		t.Fatal("samDialRaw: want an error, no listener on that port")
	}
}

func TestSamSessionCreateSuccess(t *testing.T) {
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		if !strings.HasPrefix(cmdLine, "SESSION CREATE") {
			return
		}
		rw.WriteString("SESSION STATUS RESULT=OK DESTINATION=abc123\n")
		rw.Flush()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := samSessionCreate(ctx, b.addr(), "sess1", "TRANSIENT")
	if err != nil {
		t.Fatalf("samSessionCreate: %v", err)
	}
	conn.Close()
}

func TestSamSessionCreateFailure(t *testing.T) {
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		if !strings.HasPrefix(cmdLine, "SESSION CREATE") {
			return
		}
		rw.WriteString("SESSION STATUS RESULT=DUPLICATED_ID\n")
		rw.Flush()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := samSessionCreate(ctx, b.addr(), "sess1", "TRANSIENT"); err == nil {
		t.Fatal("samSessionCreate: want an error for RESULT != OK")
	}
}

func TestSamDialSuccess(t *testing.T) {
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		if !strings.HasPrefix(cmdLine, "STREAM CONNECT") {
			return
		}
		rw.WriteString("STREAM STATUS RESULT=OK\n")
		rw.Flush()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := samDial(ctx, b.addr(), "sess1", "destbase64")
	if err != nil {
		t.Fatalf("samDial: %v", err)
	}
	defer conn.Close()
}

func TestSamDialFailure(t *testing.T) {
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		if !strings.HasPrefix(cmdLine, "STREAM CONNECT") {
			return
		}
		rw.WriteString("STREAM STATUS RESULT=CANT_REACH_PEER\n")
		rw.Flush()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := samDial(ctx, b.addr(), "sess1", "destbase64"); err == nil {
		t.Fatal("samDial: want an error for RESULT != OK")
	}
}

func TestSamListenerAcceptAndClose(t *testing.T) {
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		if !strings.HasPrefix(cmdLine, "STREAM ACCEPT") {
			return
		}
		rw.WriteString("STREAM STATUS RESULT=OK\n")
		rw.WriteString("peerdestinationbase64\n")
		rw.Flush()
		// Keeps the connection open until the test closes it, as a real
		// SAM bridge would with an actually accepted stream.
		io.Copy(io.Discard, rw)
	})

	l := newSAMListener(b.addr(), "sess1", samAddr("peer.b32.i2p"))
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	sc, ok := conn.(*samConn)
	if !ok {
		t.Fatalf("Accept: type %T, want *samConn", conn)
	}
	if sc.peerDest != "peerdestinationbase64" {
		t.Fatalf("peerDest = %q, want peerdestinationbase64", sc.peerDest)
	}
	conn.Close()

	if l.Addr().String() != "peer.b32.i2p" {
		t.Fatalf("Addr() = %q, want peer.b32.i2p", l.Addr())
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := l.Accept(); err != net.ErrClosed {
		t.Fatalf("Accept after Close: err = %v, want net.ErrClosed", err)
	}
}

// TestSamSessionCreateRespectsCtxTimeout verifies that a SAM bridge
// which replies to HELLO but then stays silent on SESSION CREATE (a slow
// or stuck i2pd) doesn't leave the caller hanging indefinitely: a ctx
// with a short timeout must unblock rw.ReadString within a reasonable
// window, not until the test's own timeout.
func TestSamSessionCreateRespectsCtxTimeout(t *testing.T) {
	silence := make(chan struct{})
	t.Cleanup(func() { close(silence) })
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		<-silence // never replies to SESSION CREATE
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := samSessionCreate(ctx, b.addr(), "sess1", "TRANSIENT")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("samSessionCreate: want an error for the ctx timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("samSessionCreate didn't unblock within the ctx timeout — the read ignores ctx")
	}
}

// TestSamDialRespectsCtxTimeout — same guarantee as above, for STREAM CONNECT.
func TestSamDialRespectsCtxTimeout(t *testing.T) {
	silence := make(chan struct{})
	t.Cleanup(func() { close(silence) })
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		<-silence // never replies to STREAM CONNECT
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := samDial(ctx, b.addr(), "sess1", "destbase64")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("samDial: want an error for the ctx timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("samDial didn't unblock within the ctx timeout — the read ignores ctx")
	}
}

// TestSamListenerAcceptUnblocksOnClose verifies the same guarantee
// extended to Accept() (net.Listener, no per-call ctx available: here
// the correct context to honor is l.ctx, canceled by Close()) — a
// Close() during an in-flight STREAM ACCEPT (a SAM bridge that replies
// to HELLO but then stays silent) must not leave Accept() blocked
// forever, even after the listener is closed.
func TestSamListenerAcceptUnblocksOnClose(t *testing.T) {
	silence := make(chan struct{})
	t.Cleanup(func() { close(silence) })
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		<-silence // never replies to STREAM ACCEPT
	})

	l := newSAMListener(b.addr(), "sess1", samAddr("peer.b32.i2p"))

	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()

	time.Sleep(50 * time.Millisecond) // gives Accept() time to enter the blocking round-trip
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept: want an error after Close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept didn't unblock within the timeout after Close — the read ignores l.ctx")
	}
}

func TestFanInListenerAcceptsFromLocal(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	// A fake SAM bridge that replies to HELLO but then stays silent on
	// STREAM ACCEPT (blocks indefinitely, never an error nor a success)
	// — avoids the intrinsic race of a SAM address that fails
	// IMMEDIATELY: that failure would arrive on errCh at an unpredictable
	// moment relative to the "local" connection this test verifies, and
	// select() between the two might pick the error.
	silence := make(chan struct{})
	t.Cleanup(func() { close(silence) })
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		<-silence
	})
	quietSAM := newSAMListener(b.addr(), "sessX", samAddr("quiet"))

	fi := newFanInListener(local, quietSAM)
	defer fi.Close()

	go func() {
		c, err := net.Dial("tcp", local.Addr().String())
		if err == nil {
			c.Close()
		}
	}()

	conn, err := fi.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	conn.Close()

	if fi.Addr().String() != local.Addr().String() {
		t.Fatalf("Addr() = %q, want %q", fi.Addr(), local.Addr())
	}
}

func TestFanInListenerCloseUnblocksAccept(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	deadSAM := newSAMListener("127.0.0.1:1", "sessX", samAddr("dead"))
	fi := newFanInListener(local, deadSAM)

	done := make(chan error, 1)
	go func() {
		_, err := fi.Accept()
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := fi.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept: want an error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept didn't unblock within the timeout after Close")
	}
}
