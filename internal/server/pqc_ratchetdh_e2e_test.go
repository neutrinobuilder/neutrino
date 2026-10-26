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

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"neutrino/internal/client"
	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// TestPQCSignWithRatchetDHTwoMemberRoom verifies that enabling /sec-pqc-sign
// in a two-member room (ratchetDH active) doesn't break the ratchet. Covers
// a real bidirectional exchange (A→B, B→A, then two more rounds) with both
// sides ML-DSA-65-signed, both the DH mix (which depends on idx/dh/dhr
// inside the same signed ciphertext) and the pqc_sig verification (which
// depends on the exact ciphertext sent on the wire) must stay correct
// message by message.
func TestPQCSignWithRatchetDHTwoMemberRoom(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	registry := serverhs.NewRoomRegistry()
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
	registry.AddSecret("room-pqc-dh", secretA, "alice", identityPubA, []byte("device-A"),
		staticResolver(shared.RelPeerKey{Pub: devAPub}, shared.RelSigningKey{Priv: hostPriv}))
	registry.AddSecret("room-pqc-dh", secretB, "bob", identityPubB, []byte("device-B"),
		staticResolver(shared.RelPeerKey{Pub: devBPub}, shared.RelSigningKey{Priv: hostPriv}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	mldsaPubA, mldsaPrivA, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mldsaPubB, mldsaPrivB, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signA := func(ciphertext []byte, ts string) []byte {
		return shared.SignPQCSig(mldsaPrivA, string(ciphertext), ts)
	}
	signB := func(ciphertext []byte, ts string) []byte {
		return shared.SignPQCSig(mldsaPrivB, string(ciphertext), ts)
	}

	// ratchetDH=true on both, exactly like a two-member room
	// (cmdInvite/cmdJoin: len(members)==2).
	cliA := client.New(host, port, "alice", secretA, true, nil, nil, signA,
		shared.RelSigningKey{Priv: devAPriv}, shared.RelPeerKey{Pub: hostPub})
	if err := cliA.Connect(ctx); err != nil {
		t.Fatalf("A: Connect: %v", err)
	}
	cliB := client.New(host, port, "bob", secretB, true, nil, nil, signB,
		shared.RelSigningKey{Priv: devBPriv}, shared.RelPeerKey{Pub: hostPub})
	if err := cliB.Connect(ctx); err != nil {
		t.Fatalf("B: Connect: %v", err)
	}

	// B reads its own "init" frame (A was already connected) to learn A's
	// session_pub/mlkem_pub, never consumed by Connect() itself, it's up
	// to the caller (tui.go, case "init"), replicated by hand
	// here.
	initB := readUntil(t, ctx, cliB, "init")
	usersB, _ := initB["users"].([]any)
	var aUserID string
	for _, u := range usersB {
		um, _ := u.(map[string]any)
		if um["username"] == "alice" {
			aUserID, _ = um["user_id"].(string)
			if sp, _ := um["session_pub"].(string); sp != "" {
				cliB.RegisterSessionPub(aUserID, sp)
			}
			if mk := decodeMLKEMPubFieldForTest(um); mk != nil {
				cliB.RegisterMLKEMPub(aUserID, mk)
			}
		}
	}
	if aUserID == "" {
		t.Fatal("B's init: alice not found in users[]")
	}

	// Bidirectional sender_key exchange, same path as tui.go.
	joinedA := readUntil(t, ctx, cliA, "user_joined")
	bUserID, _ := joinedA["user_id"].(string)
	if sp, _ := joinedA["session_pub"].(string); sp != "" {
		cliA.RegisterSessionPub(bUserID, sp)
	}
	if mk := decodeMLKEMPubFieldForTest(joinedA); mk != nil {
		cliA.RegisterMLKEMPub(bUserID, mk)
	}
	if err := cliA.SendSenderKey(ctx, bUserID); err != nil {
		t.Fatalf("A SendSenderKey: %v", err)
	}

	skFrameB := readUntil(t, ctx, cliB, "sender_key")
	payloadB, _ := skFrameB["payload"].(string)
	if err := cliB.StorePeerSenderKey(aUserID, payloadB); err != nil {
		t.Fatalf("B StorePeerSenderKey: %v", err)
	}

	if err := cliB.SendSenderKey(ctx, aUserID); err != nil {
		t.Fatalf("B SendSenderKey: %v", err)
	}
	skFrameA := readUntil(t, ctx, cliA, "sender_key")
	payloadA, _ := skFrameA["payload"].(string)
	if err := cliA.StorePeerSenderKey(bUserID, payloadA); err != nil {
		t.Fatalf("A StorePeerSenderKey: %v", err)
	}

	cliA.SetPQCSign(true)
	cliB.SetPQCSign(true)

	type step struct {
		from, to *client.Client
		fromPub  *mldsa65.PublicKey
		fromName string
		text     string
	}
	steps := []step{
		{cliA, cliB, mldsaPubA, "alice", "first message A->B"},
		{cliB, cliA, mldsaPubB, "bob", "reply B->A, the DH mix kicks in on B's side"},
		{cliA, cliB, mldsaPubA, "alice", "second A->B, DH mix on A's side too"},
		{cliB, cliA, mldsaPubB, "bob", "second B->A"},
	}

	for i, s := range steps {
		msgID, err := s.from.Send(ctx, s.text, nil)
		if err != nil {
			t.Fatalf("step %d (%s): Send: %v", i, s.fromName, err)
		}

		// The sender must receive its own self-echo.
		echo := readUntil(t, ctx, s.from, "message")
		edata, _ := echo["data"].(map[string]any)
		if parseMsgIDForTest(edata["msg_id"]) != msgID {
			t.Fatalf("step %d (%s): unexpected self-echo msg_id", i, s.fromName)
		}
		if _, _, ok := s.from.TakeSentText(msgID); !ok {
			t.Fatalf("step %d (%s): TakeSentText failed on its own self-echo", i, s.fromName)
		}

		// The recipient receives, decrypts, and verifies pqc_sig.
		msg := readUntil(t, ctx, s.to, "message")
		mdata, _ := msg["data"].(map[string]any)
		kid, _ := mdata["kid"].(string)
		rawText, _ := mdata["text"].(string)
		idxF, _ := mdata["idx"].(float64)
		from, plaintext, _, _ := s.to.DecryptMsg(kid, rawText, uint64(idxF))
		if from != s.fromName || plaintext != s.text {
			t.Fatalf("step %d: decrypt want (%q, %q), got (%q, %q)", i, s.fromName, s.text, from, plaintext)
		}

		pqcSigB64, _ := mdata["pqc_sig"].(string)
		pqcTS, _ := mdata["pqc_ts"].(string)
		if pqcSigB64 == "" || pqcTS == "" {
			t.Fatalf("step %d (%s): pqc_sig/pqc_ts missing from the frame despite SetPQCSign(true)", i, s.fromName)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(pqcSigB64)
		if err != nil {
			t.Fatalf("step %d: pqc_sig is not valid base64: %v", i, err)
		}
		if !shared.VerifyPQCSig(s.fromPub, rawText, pqcTS, sigBytes) {
			t.Errorf("step %d (%s): VerifyPQCSig failed on the received message, ciphertext=%q ts=%q", i, s.fromName, rawText, pqcTS)
		}
	}
}
