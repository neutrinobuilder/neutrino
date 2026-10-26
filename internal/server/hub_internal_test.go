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

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestWriteLoopDrainsAndZeroesQueueOnError verifies that on the first
// write error, writeLoop drains and zeroes every frame still queued in
// oc.outCh, not just the one that just failed, otherwise the remaining
// frames would stay unzeroed on the heap until garbage collection,
// contradicting zeroBytes's stated goal ("sensitive payload bytes do not
// linger"). Internal package (not server_test) to inspect
// oc.outCh/enqueue directly, otherwise not observable from Hub's public
// API alone.
func TestWriteLoopDrainsAndZeroesQueueOnError(t *testing.T) {
	hub := NewHub()

	// srvConnCh delivers the SERVER-SIDE connection: writeLoop is started
	// by hand below (not through hub.Register, which would spawn its own
	// goroutine with no way for the test to know when it's done) to get a
	// clean completion signal (done, below) instead of polling ConnCount,
	// the latter updates as soon as Unregister removes the entry from the
	// map, BEFORE writeLoop has finished draining the rest of the queue:
	// reading the payloads right after seeing ConnCount==0 would be a
	// genuine race with the drain still in progress.
	srvConnCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		srvConnCh <- conn
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	var srvConn *websocket.Conn
	select {
	case srvConn = <-srvConnCh:
	case <-time.After(2 * time.Second):
		t.Fatal("server-side connection didn't arrive in time")
	}

	oc := &outConn{conn: srvConn, outCh: make(chan []byte, outboundQueueSize), hub: hub, userID: "a"}
	hub.mu.Lock()
	hub.conns["a"] = oc
	hub.mu.Unlock()

	done := make(chan struct{})
	go func() {
		oc.writeLoop()
		close(done)
	}()

	// Closes the client side without responding: the server's next Write
	// on this connection fails (RST/broken pipe), triggering writeLoop's
	// error path.
	clientConn.CloseNow()

	// Queues several frames right after, with good probability they land
	// in the channel buffer before writeLoop completes the first failed
	// Write, leaving more than one "queued" at the moment of the error.
	// Under hub.mu.RLock(), as all real callers of enqueue do
	// (Send/SendBytes/broadcastRaw/multicastRaw), enqueue has no internal
	// synchronization of its own, the caller's contract is to hold the
	// RLock to exclude a concurrent Unregister (and thus a
	// close(oc.outCh)); without it, this would be a genuine race in the
	// test itself, not in the code under test.
	payloads := make([][]byte, 5)
	for i := range payloads {
		payloads[i] = []byte("secret-" + string(rune('a'+i)))
		hub.mu.RLock()
		enqueue(oc, payloads[i])
		hub.mu.RUnlock()
	}

	// clean happens-before: the test reads the payloads only AFTER
	// receiving from done, which writeLoop closes only when finished,
	// drain included.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("writeLoop didn't exit after the write error")
	}

	for i, p := range payloads {
		for _, b := range p {
			if b != 0 {
				t.Fatalf("payload %d not zeroed after the write error: %q", i, p)
			}
		}
	}
}

// TestSendBytesZeroesDataAfterWrite verifies that data passed to
// SendBytes is zeroed once writeLoop has written it. writeLoop is started
// by hand (done, below) so the bytes are inspected only after it has
// exited: the zeroing happens after Write returns, so a check made as
// soon as the peer receives the frame would race with it.
func TestSendBytesZeroesDataAfterWrite(t *testing.T) {
	hub := NewHub()

	srvConnCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		srvConnCh <- conn
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.CloseNow()

	var srvConn *websocket.Conn
	select {
	case srvConn = <-srvConnCh:
	case <-time.After(2 * time.Second):
		t.Fatal("server-side connection didn't arrive in time")
	}

	oc := &outConn{conn: srvConn, outCh: make(chan []byte, outboundQueueSize), hub: hub, userID: "a"}
	hub.mu.Lock()
	hub.conns["a"] = oc
	hub.mu.Unlock()

	done := make(chan struct{})
	go func() {
		oc.writeLoop()
		close(done)
	}()

	data := []byte(`{"text":"direct bytes"}`)
	if err := hub.SendBytes(context.Background(), "a", data); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, got, err := clientConn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != `{"text":"direct bytes"}` {
		t.Fatalf("received %q, want the frame passed to SendBytes", got)
	}

	// Closing the queue ends writeLoop; reading data only after done gives
	// a clean happens-before with the zeroing.
	hub.Unregister("a")
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("writeLoop didn't exit after Unregister")
	}

	for i, b := range data {
		if b != 0 {
			t.Fatalf("SendBytes: byte %d not zeroed after sending", i)
		}
	}
}
