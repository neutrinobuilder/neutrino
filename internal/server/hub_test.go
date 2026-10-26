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

package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	serverhs "neutrino/internal/server"
)

type testMsg struct {
	Text string `json:"text"`
}

// newTestHub starts a test WS server that registers each connection in hub
// under the id passed as a query param, then keeps reading until the client
// closes, mimics the real read loop in ws.go, necessary because
// Broadcast/Multicast only detect dead connections on the first failed
// Write.
func newTestHub(t *testing.T, ids []string) (hub *serverhs.Hub, conns map[string]*websocket.Conn) {
	t.Helper()
	hub = serverhs.NewHub()
	registered := make(chan struct{}, len(ids))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		hub.Register(id, conn)
		registered <- struct{}{}
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conns = make(map[string]*websocket.Conn)
	for _, id := range ids {
		c, _, err := websocket.Dial(context.Background(), wsURL+"?id="+id, nil)
		if err != nil {
			t.Fatalf("dial %s: %v", id, err)
		}
		conns[id] = c
		t.Cleanup(func() { c.CloseNow() })
	}
	for range ids {
		<-registered
	}
	return hub, conns
}

func readWithTimeout(t *testing.T, conn *websocket.Conn, d time.Duration) (testMsg, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var m testMsg
	err := wsjson.Read(ctx, conn, &m)
	return m, err
}

func TestHubRegisterUnregisterConnCount(t *testing.T) {
	hub, _ := newTestHub(t, []string{"a", "b", "c"})
	if n := hub.ConnCount(); n != 3 {
		t.Fatalf("ConnCount: want 3, got %d", n)
	}
	hub.Unregister("b")
	if n := hub.ConnCount(); n != 2 {
		t.Fatalf("ConnCount after Unregister: want 2, got %d", n)
	}
}

func TestHubBroadcastExcludesSender(t *testing.T) {
	hub, conns := newTestHub(t, []string{"a", "b", "c"})
	hub.Broadcast(context.Background(), testMsg{Text: "hello"}, "a")

	for _, id := range []string{"b", "c"} {
		m, err := readWithTimeout(t, conns[id], 2*time.Second)
		if err != nil {
			t.Fatalf("%s: want the message, error: %v", id, err)
		}
		if m.Text != "hello" {
			t.Fatalf("%s: want text 'hello', got %q", id, m.Text)
		}
	}

	if _, err := readWithTimeout(t, conns["a"], 200*time.Millisecond); err == nil {
		t.Fatal("a: excluded from the broadcast but received a message")
	}
}

func TestHubMulticastBytesZeroesData(t *testing.T) {
	hub, conns := newTestHub(t, []string{"a", "b", "c"})
	data := []byte(`{"text":"multicast secret"}`)

	hub.MulticastBytes(context.Background(), []string{"a", "c"}, data)

	for _, id := range []string{"a", "c"} {
		m, err := readWithTimeout(t, conns[id], 2*time.Second)
		if err != nil {
			t.Fatalf("%s: want the message, error: %v", id, err)
		}
		if m.Text != "multicast secret" {
			t.Fatalf("%s: unexpected text %q", id, m.Text)
		}
	}
	if _, err := readWithTimeout(t, conns["b"], 200*time.Millisecond); err == nil {
		t.Fatal("b: not among the recipients but received a message")
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("MulticastBytes: byte %d not zeroed after sending", i)
		}
	}
}

func TestHubSendSingle(t *testing.T) {
	hub, conns := newTestHub(t, []string{"a", "b"})
	if err := hub.Send(context.Background(), "a", testMsg{Text: "direct"}); err != nil {
		t.Fatal(err)
	}
	m, err := readWithTimeout(t, conns["a"], 2*time.Second)
	if err != nil {
		t.Fatalf("a: want the message, error: %v", err)
	}
	if m.Text != "direct" {
		t.Fatalf("want text 'direct', got %q", m.Text)
	}
	if _, err := readWithTimeout(t, conns["b"], 200*time.Millisecond); err == nil {
		t.Fatal("b: not the recipient but received a message")
	}
}

func TestHubSendUnknownUserIsNoop(t *testing.T) {
	hub := serverhs.NewHub()
	if err := hub.Send(context.Background(), "unknown", testMsg{Text: "x"}); err != nil {
		t.Fatalf("Send to an unknown user: want nil, got %v", err)
	}
}

// TestHubSendConcurrentWithUnregisterNoRace guards against a TOCTOU race:
// Send/SendBytes must never release h.mu.RUnlock() BEFORE enqueue(oc, data)
// if another goroutine called Unregister(userID) in that window (e.g.
// writeLoop itself on its first write error), oc.outCh would get closed
// right there, and enqueue would write to a closed channel: an immediate Go
// panic ("send on closed channel"), not interceptable from its own
// select/default, kills the whole process, not just the connection
// involved. enqueue must stay under the same RLock as the lookup, same
// pattern already used by broadcastRaw/multicastRaw. This test fires
// concurrent Send/SendBytes and Unregister/Register on the same userID for
// a short period: under -race, it fails on a data race even if no panic
// manifests during a single run (the race is timing-dependent, not
// deterministic).
func TestHubSendConcurrentWithUnregisterNoRace(t *testing.T) {
	hub, conns := newTestHub(t, []string{"a"})
	conn := conns["a"]

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = hub.Send(context.Background(), "a", testMsg{Text: "x"})
				_ = hub.SendBytes(context.Background(), "a", []byte(`{"text":"y"}`))
			}
		})
	}
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			hub.Unregister("a")
			hub.Register("a", conn)
		}
	})

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestHubBroadcastPrunesDeadConnections verifies that a connection closed
// by the client is removed from the map on the first failed Write
// ("second pass" cleanup).
func TestHubBroadcastPrunesDeadConnections(t *testing.T) {
	hub, conns := newTestHub(t, []string{"a", "b"})
	conns["b"].CloseNow()

	deadline := time.Now().Add(3 * time.Second)
	for hub.ConnCount() != 1 && time.Now().Before(deadline) {
		hub.Broadcast(context.Background(), testMsg{Text: "ping"}, "")
		time.Sleep(20 * time.Millisecond)
	}
	if n := hub.ConnCount(); n != 1 {
		t.Fatalf("ConnCount after b closes: want 1, got %d", n)
	}
}
