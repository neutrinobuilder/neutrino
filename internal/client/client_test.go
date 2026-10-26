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

package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// TestDecryptMsgDoesNotAdvanceChainOnFailure covers the invariant that a
// failed decrypt must not commit peerChainKeys/peerMsgIdx — committing
// on failure would turn a single isolated hiccup (a lost or corrupted
// packet) into a permanent, cascading misalignment where no subsequent
// message, however well-formed, could ever decrypt again. On the same
// keyID/idx, a failed attempt must leave no trace, and a subsequent
// attempt with the chain still in place must decrypt correctly.
func TestDecryptMsgDoesNotAdvanceChainOnFailure(t *testing.T) {
	senderKey := make([]byte, 32)
	for i := range senderKey {
		senderKey[i] = byte(i)
	}
	keyID := shared.DeriveKeyID(senderKey)
	chain0 := shared.InitChainKey(senderKey)

	receiver := New("127.0.0.1", 0, "receiver", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	receiver.peerChainKeys[keyID] = append([]byte(nil), chain0...)
	receiver.peerMsgIdx[keyID] = 0

	from, plaintext, _, _ := receiver.DecryptMsg(keyID, "!!! not a valid ciphertext !!!", 0)
	if plaintext != "[decrypt failed]" {
		t.Fatalf("want '[decrypt failed]', got plaintext=%q from=%q", plaintext, from)
	}
	if !bytes.Equal(receiver.peerChainKeys[keyID], chain0) {
		t.Error("the chain key must not advance after a failed decrypt")
	}
	if receiver.peerMsgIdx[keyID] != 0 {
		t.Errorf("peerMsgIdx must not advance after a failed decrypt, got %d", receiver.peerMsgIdx[keyID])
	}

	// A real message, correctly encrypted from the same position (idx 0,
	// chain0): must decrypt successfully, proving the failed attempt
	// above didn't corrupt the state.
	msgKey, nextChain := shared.DeriveChainStep(chain0)
	payload := sealedMsg{F: "sender", T: "hello"}
	plain, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	enc, err := shared.Encrypt(msgKey, plain, seqBytes(0))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	from, plaintext, _, _ = receiver.DecryptMsg(keyID, enc, 0)
	if plaintext != "hello" || from != "sender" {
		t.Fatalf("want a successful decrypt after the previous failure, got from=%q plaintext=%q", from, plaintext)
	}
	if !bytes.Equal(receiver.peerChainKeys[keyID], nextChain) {
		t.Error("the chain key must advance correctly after a successful decrypt")
	}
	if receiver.peerMsgIdx[keyID] != 1 {
		t.Errorf("peerMsgIdx: want 1 after a successful decrypt, got %d", receiver.peerMsgIdx[keyID])
	}
}

// TestDecryptMsgReturnsReplyTo covers the explicit reply reference: RT
// travels inside the ciphertext (sealedMsg) and DecryptMsg returns it
// intact to the caller — 0 when absent, the exact value chosen by the
// sender otherwise.
func TestDecryptMsgReturnsReplyTo(t *testing.T) {
	senderKey := make([]byte, 32)
	for i := range senderKey {
		senderKey[i] = byte(i)
	}
	keyID := shared.DeriveKeyID(senderKey)
	chain0 := shared.InitChainKey(senderKey)

	receiver := New("127.0.0.1", 0, "receiver", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	receiver.peerChainKeys[keyID] = append([]byte(nil), chain0...)
	receiver.peerMsgIdx[keyID] = 0

	msgKey, _ := shared.DeriveChainStep(chain0)
	payload := sealedMsg{F: "sender", T: "hello", RT: 27}
	plain, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	enc, err := shared.Encrypt(msgKey, plain, seqBytes(0))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	from, plaintext, _, replyTo := receiver.DecryptMsg(keyID, enc, 0)
	if from != "sender" || plaintext != "hello" {
		t.Fatalf("decrypt failed: from=%q plaintext=%q", from, plaintext)
	}
	if replyTo != 27 {
		t.Errorf("replyTo: want 27, got %d", replyTo)
	}
}

// TestSendReplyIncludesReplyToInSentTextCache covers the sending side's
// propagation: SendReply saves replyTo alongside the text in the
// self-echo cache (sentTexts) — necessary because the self-echo
// (tui.go) skips the receiving ratchet and so would never decrypt
// sealedMsg.RT on its own.
func TestSendReplyIncludesReplyToInSentTextCache(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	cli.Conn = conn

	msgID, err := cli.SendReply(context.Background(), "hello", nil, 42)
	if err != nil {
		t.Fatalf("SendReply: %v", err)
	}
	text, replyTo, ok := cli.TakeSentText(msgID)
	if !ok {
		t.Fatal("want an entry in sentTexts after SendReply")
	}
	if text != "hello" {
		t.Errorf("text: want 'hello', got %q", text)
	}
	if replyTo != 42 {
		t.Errorf("replyTo: want 42, got %d", replyTo)
	}
}

// TestDecryptMsgRejectsFutureIdxWithoutAdvancing: an idx that arrives
// before its turn must never advance the chain to try to "recover" it —
// the caller buffers it on its own (see Client.ExpectedIdx) and
// resubmits it here only when its turn really comes. If DecryptMsg is
// called with a future idx anyway (defensive, never the normal path),
// it must simply reject it without touching the state.
func TestDecryptMsgRejectsFutureIdxWithoutAdvancing(t *testing.T) {
	senderKey := make([]byte, 32)
	for i := range senderKey {
		senderKey[i] = byte(i)
	}
	keyID := shared.DeriveKeyID(senderKey)
	chain0 := shared.InitChainKey(senderKey)

	receiver := New("127.0.0.1", 0, "receiver", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	receiver.peerChainKeys[keyID] = append([]byte(nil), chain0...)
	receiver.peerMsgIdx[keyID] = 0

	from, plaintext, _, _ := receiver.DecryptMsg(keyID, "anything, never decrypted", 3)
	if from != "" {
		t.Fatalf("want an empty from for a future idx, got %q (plaintext=%q)", from, plaintext)
	}
	if !bytes.Equal(receiver.peerChainKeys[keyID], chain0) {
		t.Error("the chain key must not advance for a future idx — no fast-forward")
	}
	if receiver.peerMsgIdx[keyID] != 0 {
		t.Errorf("peerMsgIdx must not advance for a future idx, got %d", receiver.peerMsgIdx[keyID])
	}
}

// TestExpectedIdx covers the contract the caller uses to decide whether
// to buffer, treat as a duplicate, or process an arrival right away.
func TestExpectedIdx(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})

	if _, known := cli.ExpectedIdx("keyid-never-seen"); known {
		t.Error("ExpectedIdx: a never-registered key must report known=false")
	}

	senderKey := make([]byte, 32)
	for i := range senderKey {
		senderKey[i] = byte(i)
	}
	keyID := shared.DeriveKeyID(senderKey)
	cli.peerChainKeys[keyID] = shared.InitChainKey(senderKey)
	cli.peerMsgIdx[keyID] = 0

	idx, known := cli.ExpectedIdx(keyID)
	if !known || idx != 0 {
		t.Fatalf("ExpectedIdx just registered: want known=true idx=0, got known=%v idx=%d", known, idx)
	}

	msgKey, _ := shared.DeriveChainStep(cli.peerChainKeys[keyID])
	payload := sealedMsg{F: "sender", T: "hello"}
	plain, _ := json.Marshal(payload)
	enc, err := shared.Encrypt(msgKey, plain, seqBytes(0))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if from, _, _, _ := cli.DecryptMsg(keyID, enc, 0); from != "sender" {
		t.Fatalf("DecryptMsg: want success, got from=%q", from)
	}

	idx, known = cli.ExpectedIdx(keyID)
	if !known || idx != 1 {
		t.Errorf("ExpectedIdx after a successful decrypt: want known=true idx=1, got known=%v idx=%d", known, idx)
	}
}

// TestSendPopulatesSentTextsBeforeWrite verifies that Send() populates
// sentTexts before the network write: on a local connection (the room's
// host, in loopback toward its own server) the server's self-echo can be
// processed by the read goroutine before the write completes, and must
// still find the plaintext. Observed by forcing the write to fail and
// verifying the entry exists anyway (cleaned up by the FIFO like any
// other — see maxSentTextCache).
func TestSendPopulatesSentTextsBeforeWrite(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn := newTestWSConn(t)
	cli.Conn = conn
	conn.CloseNow() // wsjson.Write inside Send() must fail

	if _, err := cli.Send(context.Background(), "are you there?", nil); err == nil {
		t.Fatal("want a send error with the connection already closed")
	}

	if len(cli.sentTexts) != 1 {
		t.Fatalf("want 1 entry in sentTexts even with the write failed, got %d", len(cli.sentTexts))
	}
	for _, e := range cli.sentTexts {
		if e.text != "are you there?" {
			t.Errorf("want text 'are you there?' in the cache, got %q", e.text)
		}
	}
}

// TestRegisterUserPrunesStaleSessionPub covers the invariant that every
// reconnection of the same peer (frequent over I2P, rare over Tor)
// assigns them a new session user_id. Without pruning, peerSessionPubs
// would accumulate one dead entry per past reconnection — never removed
// for the life of the process — visible in RotateSenderKey as a growing
// "distributing to N peers" count in a room with a single other member.
// RegisterUser must remove the previous user_id's entry for the same
// identity key, both in peerSessionPubs and in members.
func TestRegisterUserPrunesStaleSessionPub(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})

	pub1 := randPub(t)
	cli.RegisterUser("uid-1", "peer", testIdentity("peer"))
	cli.RegisterSessionPub("uid-1", pub1)

	if _, ok := cli.peerSessionPubs["uid-1"]; !ok {
		t.Fatal("peerSessionPubs[uid-1] should be present after the first registration")
	}

	// The peer reconnects: same identity key, new user_id.
	pub2 := randPub(t)
	cli.RegisterUser("uid-2", "peer", testIdentity("peer"))
	cli.RegisterSessionPub("uid-2", pub2)

	if _, ok := cli.peerSessionPubs["uid-1"]; ok {
		t.Error("peerSessionPubs[uid-1] (previous session) should have been removed after the reconnection")
	}
	if _, ok := cli.peerSessionPubs["uid-2"]; !ok {
		t.Error("peerSessionPubs[uid-2] (current session) should be present")
	}
	if len(cli.peerSessionPubs) != 1 {
		t.Errorf("peerSessionPubs: want exactly 1 entry, got %d", len(cli.peerSessionPubs))
	}
	if name := cli.LookupUsername("uid-1"); name != "" {
		t.Errorf("members[uid-1] should have been removed, got %q", name)
	}
	if name := cli.LookupUsername("uid-2"); name != "peer" {
		t.Errorf("members[uid-2]: want 'peer', got %q", name)
	}
	if id := cli.LookupUserID(MemberKeyOf(testIdentity("peer"))); id != "uid-2" {
		t.Errorf("userIDByKey: want 'uid-2', got %q", id)
	}
}

// testIdentity returns a stable fake root identity key for a test member.
func testIdentity(name string) []byte {
	return []byte("identity-key-of-" + name)
}

// TestRegisterUserKeepsHomonymsApart: two members sharing a username
// but with different identity keys are two distinct members — neither
// is mistaken for a reconnect of the other.
func TestRegisterUserKeepsHomonymsApart(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.RegisterUser("uid-a", "bob", testIdentity("bob-a"))
	cli.RegisterSessionPub("uid-a", randPub(t))
	cli.RegisterUser("uid-b", "bob", testIdentity("bob-b"))
	cli.RegisterSessionPub("uid-b", randPub(t))

	if len(cli.peerSessionPubs) != 2 {
		t.Fatalf("peerSessionPubs: %d entries, want 2", len(cli.peerSessionPubs))
	}
	if got := cli.LookupUserID(MemberKeyOf(testIdentity("bob-a"))); got != "uid-a" {
		t.Errorf("first bob: userID %q, want uid-a", got)
	}
	if got := cli.LookupUserID(MemberKeyOf(testIdentity("bob-b"))); got != "uid-b" {
		t.Errorf("second bob: userID %q, want uid-b", got)
	}
	if got := cli.LookupMemberKey("uid-a"); got != MemberKeyOf(testIdentity("bob-a")) {
		t.Errorf("LookupMemberKey(uid-a) = %q", got)
	}
	cli.RegisterUser("uid-c", "carol", nil)
	if cli.LookupUsername("uid-c") != "" {
		t.Error("a member without identity key must not be registered")
	}
}

// TestRegisterUserPrunesStaleMLKEMPub is the peerMLKEMPubs equivalent of
// TestRegisterUserPrunesStaleSessionPub above: the same pruning must
// also apply to the ML-KEM-768 cache used by
// SendSenderKey/RotateSenderKey (HybridECIESEncrypt).
func TestRegisterUserPrunesStaleMLKEMPub(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})

	cli.RegisterUser("uid-1", "peer", testIdentity("peer"))
	cli.RegisterMLKEMPub("uid-1", randMLKEMPub(t))

	if _, ok := cli.peerMLKEMPubs["uid-1"]; !ok {
		t.Fatal("peerMLKEMPubs[uid-1] should be present after the first registration")
	}

	// The peer reconnects: same username, new user_id.
	cli.RegisterUser("uid-2", "peer", testIdentity("peer"))
	cli.RegisterMLKEMPub("uid-2", randMLKEMPub(t))

	if _, ok := cli.peerMLKEMPubs["uid-1"]; ok {
		t.Error("peerMLKEMPubs[uid-1] (previous session) should have been removed after the reconnection")
	}
	if _, ok := cli.peerMLKEMPubs["uid-2"]; !ok {
		t.Error("peerMLKEMPubs[uid-2] (current session) should be present")
	}
	if len(cli.peerMLKEMPubs) != 1 {
		t.Errorf("peerMLKEMPubs: want exactly 1 entry, got %d", len(cli.peerMLKEMPubs))
	}
}

// TestStorePeerSenderKeyHybridRoundtrip verifies that StorePeerSenderKey
// correctly decrypts a payload produced with HybridECIESEncrypt (the
// same mechanism used by SendSenderKey) against the receiver's X25519
// session pub and MLKEMPub.
func TestStorePeerSenderKeyHybridRoundtrip(t *testing.T) {
	receiver := New("127.0.0.1", 0, "receiver", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	receiver.mlkemDecap = mlkemDK

	senderKey := make([]byte, 32)
	for i := range senderKey {
		senderKey[i] = byte(i)
	}
	payloadB64, err := shared.HybridECIESEncrypt(receiver.sessionPriv.PublicKey(), mlkemDK.EncapsulationKey(), senderKey)
	if err != nil {
		t.Fatalf("HybridECIESEncrypt: %v", err)
	}

	if err := receiver.StorePeerSenderKey("uid-sender", payloadB64); err != nil {
		t.Fatalf("StorePeerSenderKey: %v", err)
	}

	wantKeyID := shared.DeriveKeyID(senderKey)
	if _, ok := receiver.peerChainKeys[wantKeyID]; !ok {
		t.Fatalf("peerChainKeys[%s] should be present after StorePeerSenderKey", wantKeyID)
	}
	if got := receiver.peerKeyIDs["uid-sender"]; got != wantKeyID {
		t.Errorf("peerKeyIDs[uid-sender]: want %q, got %q", wantKeyID, got)
	}
}

// randMLKEMPub generates a random ML-KEM-768 encapsulation key, as raw
// bytes the way RegisterMLKEMPub expects to receive it (decoded mlkem_pub field).
func randMLKEMPub(t *testing.T) []byte {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	return dk.EncapsulationKey().Bytes()
}

// randPub generates a random X25519 pubkey, encoded as the base64
// string RegisterSessionPub expects to receive from the server (session_pub field).
func randPub(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// newCapturingTestWSConn is the equivalent of newTestWSConn but forwards
// every frame read (decoded into map[string]any) onto a channel,
// instead of discarding it — used to inspect what Send() actually puts
// on the wire.
func newCapturingTestWSConn(t *testing.T) (*websocket.Conn, <-chan map[string]any) {
	t.Helper()
	frames := make(chan map[string]any, 4)
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

// newTestWSConn starts a minimal test WS server (accepts and reads
// until the client closes, same scheme as internal/server/hub_test.go)
// and returns the client-side connection, ready to be assigned to Client.Conn.
func newTestWSConn(t *testing.T) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// TestSendDoesNotAdvanceStateOnWriteFailure covers the invariant that
// Send() must not advance chain/idx or retire the DH ephemeral key
// BEFORE knowing whether the network write succeeded. A failed send
// (e.g. a broken local connection) must not burn a chain step or a slot
// of the ephemeral key retention window for a message that never
// reached the peer, which would misalign the DH mix without any
// message ever having been exchanged.
func TestSendDoesNotAdvanceStateOnWriteFailure(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{}) // ratchetDH active, as in two-member rooms
	conn := newTestWSConn(t)
	cli.Conn = conn

	idx0 := cli.senderMsgIdx
	chain0 := append([]byte(nil), cli.senderChainKey...)
	ephPub0 := cli.outEphPub.Bytes()

	// Break the connection BEFORE sending: wsjson.Write inside Send() must fail.
	conn.CloseNow()

	if _, err := cli.Send(context.Background(), "are you there?", nil); err == nil {
		t.Fatal("want a send error with the connection already closed")
	}

	if cli.senderMsgIdx != idx0 {
		t.Errorf("senderMsgIdx must not advance on a failed send: want %d, got %d", idx0, cli.senderMsgIdx)
	}
	if !bytes.Equal(cli.senderChainKey, chain0) {
		t.Error("senderChainKey must not advance on a failed send")
	}
	if !bytes.Equal(cli.outEphPub.Bytes(), ephPub0) {
		t.Error("the DH ephemeral key must not be retired/rotated on a failed send")
	}

	// A second send, this time on a healthy connection, must use the same
	// position (idx0) never consumed by the failed attempt above.
	conn2 := newTestWSConn(t)
	cli.Conn = conn2
	if _, err := cli.Send(context.Background(), "are you there?", nil); err != nil {
		t.Fatalf("Send on a healthy connection: %v", err)
	}
	if cli.senderMsgIdx != idx0+1 {
		t.Errorf("senderMsgIdx: want %d after a successful send, got %d", idx0+1, cli.senderMsgIdx)
	}
}

// TestSendConcurrentNoIdxRace covers the sender ratchet under
// concurrent Send() calls on the same Client (real scenario: a user
// message send and an automatic group notification, both separate
// tea.Cmd on the same tab.cli): if two of them derived the same idx
// from a not-yet-advanced chain, the duplicate frames would be dropped
// by the receiver, a silent loss. Every successful Send() must consume
// a unique, increasing idx, with no gaps or repeats, regardless of how
// many goroutines call it in parallel.
func TestSendConcurrentNoIdxRace(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{}) // ratchetDH active, the most exposed real case
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn

	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Go(func() {
			if _, err := cli.Send(context.Background(), "msg", nil); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Send failed: %v", err)
	}

	seen := make(map[uint64]bool, n)
	for i := 0; i < n; i++ {
		select {
		case f := <-frames:
			idxF, ok := f["idx"].(float64)
			if !ok {
				t.Fatalf("frame without a numeric idx: %#v", f)
			}
			idx := uint64(idxF)
			if seen[idx] {
				t.Fatalf("idx %d received twice — ratchet not serialized correctly", idx)
			}
			seen[idx] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for frame %d/%d", i+1, n)
		}
	}
	for i := uint64(0); i < n; i++ {
		if !seen[i] {
			t.Errorf("idx %d never seen — the sequence must cover 0..%d with no gaps", i, n-1)
		}
	}
	if cli.senderMsgIdx != n {
		t.Errorf("final senderMsgIdx: want %d, got %d", n, cli.senderMsgIdx)
	}
}

// TestClientConnRaceUnderReconnect covers the race on Client.Conn/
// mlkemDecap being read/written without a lock. reconnectTab (tui.go)
// calls Connect() again on the SAME Client instance — not a new one —
// and a read loop (waitForRoom→ReadMsg), a pending Send(), or the ping
// watchdog may still be in flight on that instance when the
// reconnection writes a new Conn/mlkemDecap. Without synchronization
// this is a real data race on the pointer, detectable by `go test -race`
// with a real client that (re)connects multiple times while other
// goroutines concurrently call Send/Ping/ReadMsg/Close on the same
// instance — exercises the real handshake (mandatory
// IdentityKey-per-relationship) end-to-end, not just the low-level methods.
func TestClientConnRaceUnderReconnect(t *testing.T) {
	secret := []byte("secret-race-conn-mlkemdecap-test-256bit!")
	clientRelKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatalf("GenerateRelSigningKey (client): %v", err)
	}
	clientEdPub, _, clientMLDSAPub, err := shared.RelSigningKeyPublicParts(clientRelKey)
	if err != nil {
		t.Fatalf("RelSigningKeyPublicParts (client): %v", err)
	}
	serverRelKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatalf("GenerateRelSigningKey (server): %v", err)
	}
	serverEdPub, _, serverMLDSAPub, err := shared.RelSigningKeyPublicParts(serverRelKey)
	if err != nil {
		t.Fatalf("RelSigningKeyPublicParts (server): %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		lookup := func(nonceClient, proof []byte) ([]byte, string, string, []byte, []byte, shared.RelPeerKey, shared.RelSigningKey, bool) {
			if _, ok := shared.VerifyRoomProof(secret, nonceClient, proof); ok {
				return secret, "race-room", "", nil, nil, shared.RelPeerKey{Pub: clientEdPub, MLDSAPub: clientMLDSAPub}, serverRelKey, true
			}
			return nil, "", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		if _, err := serverhs.DoServerHandshake(r.Context(), conn, lookup, nil); err != nil {
			return
		}
		for {
			var v map[string]any
			if err := wsjson.Read(r.Context(), conn, &v); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	cli := New(host, port, "racer", secret, false, nil, nil, nil, clientRelKey, shared.RelPeerKey{Pub: serverEdPub, MLDSAPub: serverMLDSAPub})

	const n = 15
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = cli.Connect(ctx)
		})
	}
	for i := 0; i < n; i++ {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, _ = cli.Send(ctx, "hello", nil)
			_ = cli.Ping(ctx)
			_, _ = cli.ReadMsg(ctx)
			cli.Close()
		})
	}
	wg.Wait()
}

// TestSendIncludesDeviceSig covers the Send()→wire round-trip for the
// device-level signature (remote_nuke): when signDeviceSig is set,
// every outgoing message carries device_sig/device_ts outside the
// ciphertext (same pattern already in use for sig/sig_ts) verifiable
// against the declared devicePub, and the latter travels INSIDE the
// ciphertext (sealedMsg.DP), not in the clear on the wire — see the
// comment on sealedMsg.DP.
func TestSendIncludesDeviceSig(t *testing.T) {
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signDeviceSig := func(ciphertext []byte, ts string) []byte {
		return shared.SignDeviceSig(devicePriv, string(ciphertext), ts)
	}

	cli := New("127.0.0.1", 0, "me", nil, false, devicePub, signDeviceSig, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn

	if _, err := cli.Send(context.Background(), "hello", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var frame map[string]any
	select {
	case frame = <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the server-side frame")
	}

	encText, _ := frame["text"].(string)
	if encText == "" {
		t.Fatal("frame without a text field")
	}
	if bytes.Contains([]byte(encText), devicePub) {
		t.Error("the ciphertext must not contain the devicePub in the clear (it must travel encrypted inside sealedMsg.DP)")
	}

	sigB64, _ := frame["device_sig"].(string)
	deviceTS, _ := frame["device_ts"].(string)
	if sigB64 == "" || deviceTS == "" {
		t.Fatal("want device_sig/device_ts populated on the frame")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("device_sig is not valid base64: %v", err)
	}
	if !shared.VerifyDeviceSig(devicePub, encText, deviceTS, sigBytes) {
		t.Error("device_sig on the wire doesn't verify against devicePub/ciphertext/device_ts")
	}
}

// TestSendOmitsPQCSigByDefault covers the default of the optional
// per-room PQC signature (hybrid PQC network identity): even with
// signMLDSA set, without an explicit SetPQCSign(true) no pqc_sig/pqc_ts
// field must appear on the wire — never active by default, ~3.3KB cost
// per signature.
func TestSendOmitsPQCSigByDefault(t *testing.T) {
	_, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signMLDSA := func(ciphertext []byte, ts string) []byte {
		return shared.SignPQCSig(mldsaPriv, string(ciphertext), ts)
	}

	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, signMLDSA, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn

	if _, err := cli.Send(context.Background(), "hello", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var frame map[string]any
	select {
	case frame = <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the server-side frame")
	}
	if _, ok := frame["pqc_sig"]; ok {
		t.Error("pqc_sig must not appear on the wire without SetPQCSign(true)")
	}
}

// TestSendIncludesPQCSigWhenEnabled covers the Send()→wire round-trip
// for the optional per-room ML-DSA-65 signature when explicitly enabled
// via SetPQCSign(true) — same scheme as TestSendIncludesDeviceSig.
func TestSendIncludesPQCSigWhenEnabled(t *testing.T) {
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signMLDSA := func(ciphertext []byte, ts string) []byte {
		return shared.SignPQCSig(mldsaPriv, string(ciphertext), ts)
	}

	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, signMLDSA, shared.RelSigningKey{}, shared.RelPeerKey{})
	if cli.PQCSign() {
		t.Fatal("PQCSign must be false by default")
	}
	cli.SetPQCSign(true)
	if !cli.PQCSign() {
		t.Fatal("PQCSign must be true after SetPQCSign(true)")
	}
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn

	if _, err := cli.Send(context.Background(), "hello", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var frame map[string]any
	select {
	case frame = <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the server-side frame")
	}

	encText, _ := frame["text"].(string)
	if encText == "" {
		t.Fatal("frame without a text field")
	}
	sigB64, _ := frame["pqc_sig"].(string)
	pqcTS, _ := frame["pqc_ts"].(string)
	if sigB64 == "" || pqcTS == "" {
		t.Fatal("want pqc_sig/pqc_ts populated on the frame")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("pqc_sig is not valid base64: %v", err)
	}
	if !shared.VerifyPQCSig(mldsaPub, encText, pqcTS, sigBytes) {
		t.Error("pqc_sig on the wire doesn't verify against mldsaPub/ciphertext/pqc_ts")
	}
}

// dhTestMsg encrypts text as a sender in a two-member room would at
// position idx of chain: DH-mixed between senderEph and the receiver's
// ephemeral recvEph (referenced by dhr). Returns the ciphertext and the
// sender's next chain key.
func dhTestMsg(t *testing.T, chain []byte, idx uint64, senderEph *ecdh.PrivateKey, recvEph *ecdh.PublicKey, text string) (string, []byte) {
	t.Helper()
	dhShared, err := senderEph.ECDH(recvEph)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	msgKey, next := shared.DeriveChainStepDH(chain, dhShared)
	plain, _ := json.Marshal(sealedMsg{
		F:   "sender",
		T:   text,
		DH:  base64.StdEncoding.EncodeToString(senderEph.PublicKey().Bytes()),
		DHR: shared.EphID(recvEph.Bytes()),
	})
	enc, err := shared.Encrypt(msgKey, plain, seqBytes(idx))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return enc, next
}

// newDHReceiver returns a two-member-room client that knows chain0 under
// keyID and has retired the ephemerals rets (oldest first, retired at
// the given times).
func newDHReceiver(t *testing.T, keyID string, chain0 []byte, rets []*ecdh.PrivateKey, at []time.Time) *Client {
	t.Helper()
	c := New("127.0.0.1", 0, "receiver", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	c.peerChainKeys[keyID] = append([]byte(nil), chain0...)
	c.peerMsgIdx[keyID] = 0
	for i, r := range rets {
		id := shared.EphID(r.PublicKey().Bytes())
		c.outEphRing[id] = r
		c.outEphOrder = append(c.outEphOrder, retiredEph{id: id, at: at[i]})
	}
	return c
}

func genEph(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// TestDecryptMsgRefusesUnretainedDHR covers a message whose dhr names an
// ephemeral of ours no longer retained: the next chain key can't be
// computed, so the message is refused without committing anything —
// never a plain step, which would diverge the chain for every later
// message. Once the ephemeral is available, the same message decrypts
// and the chain advances exactly as the sender's.
func TestDecryptMsgRefusesUnretainedDHR(t *testing.T) {
	senderKey := make([]byte, 32)
	keyID := shared.DeriveKeyID(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	recvEph, senderEph := genEph(t), genEph(t)
	enc, senderNext := dhTestMsg(t, chain0, 0, senderEph, recvEph.PublicKey(), "hi")

	c := newDHReceiver(t, keyID, chain0, nil, nil)
	if from, _, _, _ := c.DecryptMsg(keyID, enc, 0); from != "" {
		t.Fatalf("unretained dhr: decrypted from %q, want refused", from)
	}
	if !bytes.Equal(c.peerChainKeys[keyID], chain0) || c.peerMsgIdx[keyID] != 0 {
		t.Fatal("refused message advanced the chain")
	}

	id := shared.EphID(recvEph.PublicKey().Bytes())
	c.outEphRing[id] = recvEph
	c.outEphOrder = append(c.outEphOrder, retiredEph{id: id, at: time.Now()})
	from, text, _, _ := c.DecryptMsg(keyID, enc, 0)
	if from != "sender" || text != "hi" {
		t.Fatalf("retained dhr: from=%q text=%q", from, text)
	}
	if !bytes.Equal(c.peerChainKeys[keyID], senderNext) {
		t.Error("chain key differs from the sender's after the DH step")
	}
}

// TestDecryptMsgPrunesOlderEphemerals covers retention by proof of
// receipt: once the peer references one of our ephemerals, every older
// one is dropped — its later messages can only reference that one or a
// newer one.
func TestDecryptMsgPrunesOlderEphemerals(t *testing.T) {
	senderKey := make([]byte, 32)
	keyID := shared.DeriveKeyID(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	r1, r2, r3 := genEph(t), genEph(t), genEph(t)
	now := time.Now()
	c := newDHReceiver(t, keyID, chain0, []*ecdh.PrivateKey{r1, r2, r3}, []time.Time{now, now, now})

	enc, _ := dhTestMsg(t, chain0, 0, genEph(t), r2.PublicKey(), "hi")
	if from, _, _, _ := c.DecryptMsg(keyID, enc, 0); from != "sender" {
		t.Fatalf("decrypt failed")
	}
	for name, r := range map[string]*ecdh.PrivateKey{"r1": r1, "r2": r2, "r3": r3} {
		_, kept := c.outEphRing[shared.EphID(r.PublicKey().Bytes())]
		if want := name != "r1"; kept != want {
			t.Errorf("%s retained = %v, want %v", name, kept, want)
		}
	}
	if len(c.outEphOrder) != 2 {
		t.Errorf("outEphOrder holds %d entries, want 2", len(c.outEphOrder))
	}
}

// TestDecryptMsgExpiresEphemeralsPastTwiceTTL covers retention by time:
// an ephemeral retired more than twice the message TTL ago is dropped
// even if the peer still references it — the peer can never keep our
// private ephemerals alive beyond that bound.
func TestDecryptMsgExpiresEphemeralsPastTwiceTTL(t *testing.T) {
	senderKey := make([]byte, 32)
	keyID := shared.DeriveKeyID(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	old := genEph(t)
	c := newDHReceiver(t, keyID, chain0, []*ecdh.PrivateKey{old}, []time.Time{time.Now().Add(-time.Hour)})
	c.SetPendingLimits(0, 0, 0, time.Minute)

	enc, _ := dhTestMsg(t, chain0, 0, genEph(t), old.PublicKey(), "hi")
	if from, _, _, _ := c.DecryptMsg(keyID, enc, 0); from != "" {
		t.Fatalf("expired dhr: decrypted from %q, want refused", from)
	}
	if len(c.outEphRing) != 0 || len(c.outEphOrder) != 0 {
		t.Errorf("expired ephemeral still retained: ring %d, order %d", len(c.outEphRing), len(c.outEphOrder))
	}
}

// TestRotateSenderKeyKeepsRetiredEphemerals covers the rotation in a
// two-member room: the peer's messages already in flight may reference
// ephemerals retired before it, so the rotation leaves them in place.
func TestRotateSenderKeyKeepsRetiredEphemerals(t *testing.T) {
	c := New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	c.Conn = conn
	r := genEph(t)
	id := shared.EphID(r.PublicKey().Bytes())
	c.outEphRing[id] = r
	c.outEphOrder = append(c.outEphOrder, retiredEph{id: id, at: time.Now()})

	if err := c.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}
	if _, ok := c.outEphRing[id]; !ok || len(c.outEphOrder) != 1 {
		t.Error("rotation dropped a retired ephemeral")
	}
}

// TestPingSeqBaseSurvivesFloat64 covers the ping sequence numbers' wire
// round trip: decoded into a map[string]any, each one of a run must come
// back as itself (a float64 is exact only up to 2^53).
func TestPingSeqBaseSurvivesFloat64(t *testing.T) {
	base := PingSeqBase()
	for i := range uint64(16) {
		data, _ := json.Marshal(map[string]any{"seq": base + i})
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		f, _ := m["seq"].(float64)
		if got := uint64(f); got != base+i {
			t.Fatalf("seq base+%d came back as base+%d", i, int64(got)-int64(base))
		}
	}
	if next := PingSeqBase(); next < base {
		t.Errorf("PingSeqBase went backwards: %d after %d", next, base)
	}
}
