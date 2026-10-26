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

package tui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"neutrino/internal/client"
	"neutrino/internal/shared"
)

// newCapturingTestWSConnTUI is the same as newCapturingTestWSConn in
// internal/client/client_test.go, duplicated here for the same reason as
// newTestWSConn above (the two test packages do not share unexported
// symbols).
func newCapturingTestWSConnTUI(t *testing.T) (*websocket.Conn, <-chan map[string]any) {
	t.Helper()
	frames := make(chan map[string]any, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		for {
			var mm map[string]any
			if err := wsjson.Read(r.Context(), conn, &mm); err != nil {
				return
			}
			frames <- mm
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn, frames
}

// selfEchoFrameFromSent builds the "message" frame the server would send
// back to the sender (self-echo, roomDelivery.Dispatch) starting from the
// EXACT frame captured on the outgoing wire, the same fields
// wsRawMsgData actually carries (kid/text/idx/mseq/msg_id unchanged,
// gseq/from_user_id/timestamp added by the server).
func selfEchoFrameFromSent(sent map[string]any, gseq uint64, selfUserID string) map[string]any {
	return map[string]any{
		"kid":          sent["kid"],
		"text":         sent["text"],
		"idx":          sent["idx"],
		"mseq":         sent["mseq"],
		"gseq":         float64(gseq),
		"msg_id":       sent["msg_id"],
		"from_user_id": selfUserID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// TestSelfEchoSecondMessageStopsShowingOwnText verifies that, in a
// two-member room, a user keeps seeing each of their own successive
// messages in their own window. Reproduces the REAL path
// (handleIncomingMessage, not TakeSentText called directly as already
// covered elsewhere) for two consecutive self-echoes from the same sender.
func TestSelfEchoSecondMessageStopsShowingOwnText(t *testing.T) {
	cli := client.New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConnTUI(t)
	cli.Conn = conn

	tab := &roomTab{cli: cli}
	m := &model{myUsername: "me", tabs: []*roomTab{tab}, active: 0}

	const selfUserID = "self-session-id"

	// First message of our own.
	if _, err := cli.Send(context.Background(), "first", nil); err != nil {
		t.Fatalf("Send #1: %v", err)
	}
	var sent1 map[string]any
	select {
	case sent1 = <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for frame #1")
	}
	echo1 := selfEchoFrameFromSent(sent1, 1, selfUserID)
	lines1, _ := m.handleIncomingMessage(tab, 0, echo1)
	if len(lines1) != 1 || lines1[0].text != "first" || lines1[0].username != "me" {
		t.Fatalf("self-echo #1: want 1 line (\"first\", me), got %#v", lines1)
	}

	// Second message of our own, same pattern.
	if _, err := cli.Send(context.Background(), "second", nil); err != nil {
		t.Fatalf("Send #2: %v", err)
	}
	var sent2 map[string]any
	select {
	case sent2 = <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for frame #2")
	}
	echo2 := selfEchoFrameFromSent(sent2, 2, selfUserID)
	lines2, _ := m.handleIncomingMessage(tab, 0, echo2)
	if len(lines2) != 1 || lines2[0].text != "second" || lines2[0].username != "me" {
		t.Fatalf("self-echo #2: want 1 line (\"second\", me), got %#v (buffered instead of shown: %v)", lines2, tab.msgBuffer)
	}
}
