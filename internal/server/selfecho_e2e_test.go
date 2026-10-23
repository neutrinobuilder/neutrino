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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strconv"
	"testing"
	"time"

	"neutrino/internal/client"
	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// decodeMLKEMPubFieldForTest/parseMsgIDForTest locally reimplement (test in
// package server_test, with no access to the unexported sibling functions
// of tui.go) the same decoding used by real clients — see the
// comment on wsIncoming.MsgID (internal/server/ws.go) for why msg_id
// travels as a decimal string, not a JSON number.
func decodeMLKEMPubFieldForTest(raw map[string]any) []byte {
	s, _ := raw["mlkem_pub"].(string)
	if s == "" {
		return nil
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return dec
}

func parseMsgIDForTest(v any) uint64 {
	s, _ := v.(string)
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// readUntil reads frames from cli until typ matches wantType or the
// timeout expires — the exact order between frames of different types
// toward the same recipient isn't specified by the application protocol
// (only the order BETWEEN frames of the SAME type is, guaranteed by the
// per-contact FIFO queue, see hub.go), so the test doesn't assume a rigid
// sequence.
func readUntil(t *testing.T, ctx context.Context, cli *client.Client, wantType string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := cli.ReadMsg(ctx)
		if err != nil {
			t.Fatalf("ReadMsg waiting for %q: %v", wantType, err)
		}
		if typ, _ := raw["type"].(string); typ == wantType {
			return raw
		}
	}
	t.Fatalf("timeout waiting for a %q frame", wantType)
	return nil
}

// TestSendSelfEchoAndDelivery is the end-to-end test verifying that
// roomDelivery.Dispatch never excludes the sender from the fan-out — the
// server's self-echo is what the client relies on to show its own
// message in chat (TakeSentText, called only inside parseMessage
// on an incoming "message" frame — no other point in the code adds the row
// for one's own send). Covers two real clients, one real server: the
// sender must receive its own self-echo, with the gseq already assigned
// inside it (same reliable per-contact queue as anyone else, never a
// separate frame), the recipient must receive and correctly decrypt the
// message.
func TestSendSelfEchoAndDelivery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	registry := serverhs.NewRoomRegistry()
	// Two DIFFERENT members of the same room, not two devices of the same
	// identity (that case — one device per identity per room — is covered
	// by TestRoomSlotRejectsSecondDeviceSameIdentity): distinct identityPub
	// for A and B, otherwise the second Connect would be rejected with
	// ErrAlreadyConnectedElsewhere.
	identityPubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityPubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devAPub, devAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devBPub, devBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secretA, _ := shared.RandomBytes(32)
	secretB, _ := shared.RandomBytes(32)
	registry.AddSecret("room-echo", secretA, "alice", identityPubA, []byte("device-A"),
		staticResolver(shared.RelPeerKey{Pub: devAPub}, shared.RelSigningKey{Priv: hostPriv}))
	registry.AddSecret("room-echo", secretB, "bob", identityPubB, []byte("device-B"),
		staticResolver(shared.RelPeerKey{Pub: devBPub}, shared.RelSigningKey{Priv: hostPriv}))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		_ = serverhs.RunOnListener(ctx, ln, registry, nil, nil, nil, nil, serverhs.ServerConfig{})
	}()
	waitServing(t, "http://"+ln.Addr().String()+"/health")

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	cliA := client.New(host, port, "alice", secretA, false, nil, nil, nil,
		shared.RelSigningKey{Priv: devAPriv}, shared.RelPeerKey{Pub: hostPub})
	if err := cliA.Connect(ctx); err != nil {
		t.Fatalf("A: Connect: %v", err)
	}

	cliB := client.New(host, port, "bob", secretB, false, nil, nil, nil,
		shared.RelSigningKey{Priv: devBPriv}, shared.RelPeerKey{Pub: hostPub})
	if err := cliB.Connect(ctx); err != nil {
		t.Fatalf("B: Connect: %v", err)
	}

	// A receives "user_joined" for B: sender_key exchange, same path as
	// tui.go (case "user_joined").
	joined := readUntil(t, ctx, cliA, "user_joined")
	bUserID, _ := joined["user_id"].(string)
	if bUserID == "" {
		t.Fatal("user_joined without user_id")
	}
	if got, _ := joined["identity_pub"].(string); got != base64.StdEncoding.EncodeToString(identityPubB) {
		t.Fatalf("user_joined identity_pub %q, want bob's root identity key", got)
	}
	initFrame := readUntil(t, ctx, cliB, "init")
	users, _ := initFrame["users"].([]any)
	var aliceIdentity string
	for _, u := range users {
		if m, _ := u.(map[string]any); m["username"] == "alice" {
			aliceIdentity, _ = m["identity_pub"].(string)
		}
	}
	if aliceIdentity != base64.StdEncoding.EncodeToString(identityPubA) {
		t.Fatalf("init identity_pub for alice %q, want alice's root identity key", aliceIdentity)
	}
	sessionPub, _ := joined["session_pub"].(string)
	if sessionPub != "" {
		cliA.RegisterSessionPub(bUserID, sessionPub)
	}
	if mlkemPub := decodeMLKEMPubFieldForTest(joined); mlkemPub != nil {
		cliA.RegisterMLKEMPub(bUserID, mlkemPub)
	}
	if err := cliA.SendSenderKey(ctx, bUserID); err != nil {
		t.Fatalf("SendSenderKey: %v", err)
	}

	senderKeyFrame := readUntil(t, ctx, cliB, "sender_key")
	aUserID, _ := senderKeyFrame["from_user_id"].(string)
	payload, _ := senderKeyFrame["payload"].(string)
	if err := cliB.StorePeerSenderKey(aUserID, payload); err != nil {
		t.Fatalf("StorePeerSenderKey: %v", err)
	}

	msgID, err := cliA.Send(ctx, "hello", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// The sender must receive its own self-echo, without which
	// TakeSentText would never fire (see the comment on the test) —
	// already carries the assigned gseq, the server's sole acknowledgment.
	echo := readUntil(t, ctx, cliA, "message")
	data, _ := echo["data"].(map[string]any)
	echoMsgID := parseMsgIDForTest(data["msg_id"])
	if echoMsgID != msgID {
		t.Fatalf("self-echo msg_id: want %d, got %d", msgID, echoMsgID)
	}
	if gseqF, _ := data["gseq"].(float64); gseqF == 0 {
		t.Error("self-echo gseq: want non-zero")
	}
	text, replyTo, ok := cliA.TakeSentText(echoMsgID)
	if !ok || text != "hello" || replyTo != 0 {
		t.Fatalf("TakeSentText: want (\"hello\", 0, true), got (%q, %d, %v)", text, replyTo, ok)
	}

	// The recipient must receive and be able to decrypt the message.
	msg := readUntil(t, ctx, cliB, "message")
	mdata, _ := msg["data"].(map[string]any)
	kid, _ := mdata["kid"].(string)
	rawText, _ := mdata["text"].(string)
	idxF, _ := mdata["idx"].(float64)
	from, plaintext, _, _ := cliB.DecryptMsg(kid, rawText, uint64(idxF))
	if from != "alice" || plaintext != "hello" {
		t.Fatalf("B: decrypt want (alice, hello), got (%q, %q)", from, plaintext)
	}
}
