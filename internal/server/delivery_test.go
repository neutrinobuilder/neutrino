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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type deliveryTestMsg struct {
	Type string `json:"type"`
	Data struct {
		GSeq uint64 `json:"gseq"`
	} `json:"data"`
	MsgID string `json:"msg_id"`
}

// newDeliveryTestHub is the equivalent, in this internal package, of
// newTestHub (hub_test.go, package server_test), duplicated instead of
// shared because roomDelivery isn't reachable from Hub's public API, so
// these tests must live in the internal package.
func newDeliveryTestHub(t *testing.T, ids []string) (hub *Hub, conns map[string]*websocket.Conn) {
	t.Helper()
	hub = NewHub()
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

func readDeliveryMsg(t *testing.T, conn *websocket.Conn, d time.Duration) (deliveryTestMsg, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var m deliveryTestMsg
	err := wsjson.Read(ctx, conn, &m)
	return m, err
}

// hasPending reports whether identityPub still has at least one
// unacknowledged entry in its queue, same package, internal state reached
// directly without going through a public accessor.
func hasPending(rd *roomDelivery, identityPub string) bool {
	cq := rd.queueFor(identityPub)
	cq.mu.Lock()
	defer cq.mu.Unlock()
	return len(cq.items) > 0
}

// TestRoomDeliveryDispatchAssignsIncreasingGSeqAndEchoesSender covers the
// core of the mechanism: increasing gseq per message, delivered right away
// to all known connected (live) members AND to the sender itself
// (self-echo, required client-side, see the comment on Dispatch), the
// latter in the same per-member pending queue as anyone else (see
// TestRoomDeliverySenderEntersOwnQueueUntilSelfAck).
func TestRoomDeliveryDispatchAssignsIncreasingGSeqAndEchoesSender(t *testing.T) {
	hub, conns := newDeliveryTestHub(t, []string{"a", "b", "c"})
	rd := newRoomDelivery()
	for _, id := range []string{"a", "b", "c"} {
		rd.SetLive([]byte(id), id)
	}
	recipients := [][]byte{[]byte("a"), []byte("b"), []byte("c")}

	buildFrame := func(gseq uint64) []byte {
		var out deliveryTestMsg
		out.Type = "message"
		out.Data.GSeq = gseq
		out.MsgID = "m1"
		b, _ := json.Marshal(out)
		return b
	}

	gseq1 := rd.Dispatch(hub, recipients, "m1", []byte("a"), buildFrame)
	if gseq1 != 1 {
		t.Fatalf("first Dispatch: want gseq=1, got %d", gseq1)
	}

	for _, id := range []string{"a", "b", "c"} {
		m, err := readDeliveryMsg(t, conns[id], 2*time.Second)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if m.Data.GSeq != 1 {
			t.Errorf("%s: gseq want 1, got %d", id, m.Data.GSeq)
		}
	}

	gseq2 := rd.Dispatch(hub, recipients, "m2", []byte("a"), func(gseq uint64) []byte {
		var out deliveryTestMsg
		out.Data.GSeq = gseq
		out.MsgID = "m2"
		b, _ := json.Marshal(out)
		return b
	})
	if gseq2 != 2 {
		t.Fatalf("second Dispatch: want gseq=2, got %d", gseq2)
	}
}

// TestRoomDeliverySenderEntersOwnQueueUntilSelfAck verifies that if the
// sender disconnects exactly between gseq assignment and delivery of its
// own self-echo, that self-echo is not lost forever: the sender enters its
// own per-member pending queue like anyone else, and only leaves it once it
// explicitly acknowledges (Ack, client-side the "self_relay_ack" frame),
// not an implicit ack on mere delivery of the self-echo.
func TestRoomDeliverySenderEntersOwnQueueUntilSelfAck(t *testing.T) {
	hub, conns := newDeliveryTestHub(t, []string{"a", "b"})
	rd := newRoomDelivery()
	rd.SetLive([]byte("a"), "a")
	rd.SetLive([]byte("b"), "b")

	rd.Dispatch(hub, [][]byte{[]byte("a"), []byte("b")}, "m1", []byte("a"), func(gseq uint64) []byte {
		b, _ := json.Marshal(deliveryTestMsg{MsgID: "m1"})
		return b
	})
	if _, err := readDeliveryMsg(t, conns["a"], 2*time.Second); err != nil {
		t.Fatalf("self-echo never reached the sender: %v", err)
	}
	if !hasPending(rd, "a") {
		t.Fatal("the sender must have a pending queue for its own message until it self-confirms")
	}
	rd.Ack([]byte("a"), "m1")
	if hasPending(rd, "a") {
		t.Error("after Ack the sender's queue must be empty")
	}
}

// TestRoomDeliveryAckRemovesFromContactQueue covers Ack: removes ONLY from
// the confirming member's queue, never from the others (independent
// queues, no synchronization between them).
func TestRoomDeliveryAckRemovesFromContactQueue(t *testing.T) {
	hub, conns := newDeliveryTestHub(t, []string{"a", "b", "c"})
	rd := newRoomDelivery()
	for _, id := range []string{"a", "b", "c"} {
		rd.SetLive([]byte(id), id)
	}

	rd.Dispatch(hub, [][]byte{[]byte("a"), []byte("b"), []byte("c")}, "m1", []byte("a"), func(gseq uint64) []byte {
		b, _ := json.Marshal(deliveryTestMsg{MsgID: "m1"})
		return b
	})
	for _, id := range []string{"b", "c"} {
		if _, err := readDeliveryMsg(t, conns[id], 2*time.Second); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}

	if !hasPending(rd, "b") {
		t.Fatal("b's queue before the ack: want present")
	}
	rd.Ack([]byte("b"), "m1")
	if hasPending(rd, "b") {
		t.Error("b's queue after the ack: want absent")
	}
	if !hasPending(rd, "c") {
		t.Error("c's queue: b's ack must not empty it")
	}
}

// TestRoomDeliveryQueuesForOfflineMemberAndDeliversOnReconnect verifies
// that a member KNOWN to the room but not connected at this instant
// (absent from live) still remains a recipient, Dispatch queues it without
// attempting delivery; when it (re)connects (SetLive, a new session
// userID) RetryAndEvict delivers the backlog, with no queue migration
// needed (the key stays its root identityPub, stable across the
// reconnection).
func TestRoomDeliveryQueuesForOfflineMemberAndDeliversOnReconnect(t *testing.T) {
	hub, conns := newDeliveryTestHub(t, []string{"a", "b2"})
	rd := newRoomDelivery()
	rd.SetLive([]byte("a"), "a")
	// "b" is a known member (in recipients) but not yet marked live: its
	// "b2" connection already exists in the hub but roomDelivery doesn't
	// know it yet, exactly like a member who hasn't (re)connected at the
	// application level yet (ClaimIdentitySlot/SetLive not called yet).

	rd.Dispatch(hub, [][]byte{[]byte("a"), []byte("b")}, "m1", []byte("a"), func(gseq uint64) []byte {
		b, _ := json.Marshal(deliveryTestMsg{MsgID: "m1"})
		return b
	})
	if _, err := readDeliveryMsg(t, conns["a"], 2*time.Second); err != nil {
		t.Fatalf("a: %v", err)
	}
	if !hasPending(rd, "b") {
		t.Fatal("b (offline) must still have a pending queue")
	}

	rd.SetLive([]byte("b"), "b2")
	cq := rd.queueFor("b")
	cq.mu.Lock()
	for _, it := range cq.items {
		it.nextRetry = time.Now().Add(-time.Second)
	}
	cq.mu.Unlock()
	rd.RetryAndEvict(hub)

	m, err := readDeliveryMsg(t, conns["b2"], 2*time.Second)
	if err != nil {
		t.Fatalf("backlog never delivered to b after the reconnection: %v", err)
	}
	if m.MsgID != "m1" {
		t.Errorf("msg_id: want m1, got %q", m.MsgID)
	}
}

// TestRoomDeliveryRetryAndEvictResendsAfterBackoff covers the last-mile
// retry: an entry with an expired backoff is retransmitted verbatim to
// whoever is connected now. nextRetry forced into the past instead of
// waiting for deliveryRetryDelay (20s), same package, internal state
// accessible.
func TestRoomDeliveryRetryAndEvictResendsAfterBackoff(t *testing.T) {
	hub, conns := newDeliveryTestHub(t, []string{"a", "b"})
	rd := newRoomDelivery()
	rd.SetLive([]byte("a"), "a")
	rd.SetLive([]byte("b"), "b")

	rd.Dispatch(hub, [][]byte{[]byte("a"), []byte("b")}, "m1", []byte("a"), func(gseq uint64) []byte {
		b, _ := json.Marshal(deliveryTestMsg{MsgID: "m1"})
		return b
	})
	if _, err := readDeliveryMsg(t, conns["b"], 2*time.Second); err != nil {
		t.Fatalf("first send: %v", err)
	}

	cq := rd.queueFor("b")
	cq.mu.Lock()
	if len(cq.items) != 1 {
		cq.mu.Unlock()
		t.Fatalf("want 1 queued item, got %d", len(cq.items))
	}
	cq.items[0].nextRetry = time.Now().Add(-time.Second)
	cq.mu.Unlock()

	rd.RetryAndEvict(hub)

	m, err := readDeliveryMsg(t, conns["b"], 2*time.Second)
	if err != nil {
		t.Fatalf("retransmission never arrived: %v", err)
	}
	if m.MsgID != "m1" {
		t.Errorf("msg_id: want m1, got %q", m.MsgID)
	}
}

// TestRoomDeliveryRetryAndEvictKicksOnOverload covers the kick for a
// saturated queue (outboundQueueSize), closes the connection with
// statusQueueOverloaded (never StatusPolicyViolation, reserved for
// /grp-ban) and forgets the queue.
func TestRoomDeliveryRetryAndEvictKicksOnOverload(t *testing.T) {
	hub, conns := newDeliveryTestHub(t, []string{"a", "b"})
	rd := newRoomDelivery()
	rd.SetLive([]byte("b"), "b")

	cq := rd.queueFor("b")
	cq.mu.Lock()
	for range outboundQueueSize {
		cq.items = append(cq.items, &relayItem{gseq: 1, msgID: "x", data: []byte("y"), nextRetry: time.Now().Add(time.Hour)})
	}
	cq.mu.Unlock()

	rd.RetryAndEvict(hub)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := conns["b"].Read(ctx)
	if err == nil {
		t.Fatal("want b's connection to be closed (overload kick)")
	}
	if s := websocket.CloseStatus(err); s != statusQueueOverloaded {
		t.Errorf("close status: want %d (statusQueueOverloaded), got %d", statusQueueOverloaded, s)
	}
	if hasPending(rd, "b") {
		t.Error("b's queue must have been forgotten after the kick")
	}
}

// TestRoomDeliveryRedispatchReplacesQueuedFrame covers a message
// re-encrypted by its sender under a new generation (same msgID): it
// keeps the gseq first assigned, and the copy still queued for a member
// that hasn't acknowledged it is replaced by the new frame, the next
// retry delivers the new ciphertext, never the refused one.
func TestRoomDeliveryRedispatchReplacesQueuedFrame(t *testing.T) {
	hub, conns := newDeliveryTestHub(t, []string{"a", "b"})
	rd := newRoomDelivery()
	rd.SetLive([]byte("a"), "a")
	rd.SetLive([]byte("b"), "b")
	recipients := [][]byte{[]byte("a"), []byte("b")}

	frame := func(text string) func(uint64) []byte {
		return func(gseq uint64) []byte {
			var out deliveryTestMsg
			out.Type = text
			out.Data.GSeq = gseq
			out.MsgID = "m1"
			b, _ := json.Marshal(out)
			return b
		}
	}
	g1 := rd.Dispatch(hub, recipients, "m1", []byte("a"), frame("old"))
	if _, err := readDeliveryMsg(t, conns["b"], 2*time.Second); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	g2 := rd.Dispatch(hub, recipients, "m1", []byte("a"), frame("new"))
	if g2 != g1 {
		t.Errorf("re-dispatch of the same msgID: gseq %d, want %d", g2, g1)
	}
	m, err := readDeliveryMsg(t, conns["b"], 2*time.Second)
	if err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	if m.Type != "new" {
		t.Errorf("live delivery of the re-dispatch: type %q, want new", m.Type)
	}

	cq := rd.queueFor("b")
	cq.mu.Lock()
	n := len(cq.items)
	var queued deliveryTestMsg
	if n == 1 {
		_ = json.Unmarshal(cq.items[0].data, &queued)
	}
	cq.mu.Unlock()
	if n != 1 {
		t.Fatalf("b's queue holds %d entries, want 1", n)
	}
	if queued.Type != "new" || queued.Data.GSeq != g1 {
		t.Errorf("queued frame = %+v, want type new with gseq %d", queued, g1)
	}
}
