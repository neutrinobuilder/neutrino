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
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"neutrino/internal/i18n"
	"neutrino/internal/shared"
)

// DoServerHandshake runs the server-side handshake on a freshly accepted
// WebSocket connection.
//
// Sequence:
//  1. Receive ClientHello
//  2. Verify version, ML-KEM-768 format (encapsulate right away), and room_proof
//  3. Verify Sig with the peer's IdentityKey-per-relationship (known from the invite bootstrap)
//  4. Generate nonce_server and an ephemeral X25519 pair
//  5. Sign (nonce_client || nonce_server || session_pub) with OUR OWN IdentityKey-per-relationship toward that peer
//  6. Send ServerHello
//  7. Compute session_key via hybrid X25519+ML-KEM-768 + HKDF (transcript includes both session pubs)
//
// On error, closes the WebSocket with the appropriate code before returning.
//
// secretLookup receives (nonceClient, roomProof) and returns the matching
// group secret, the peer's IdentityKey-per-relationship (to verify Sig) and
// our own IdentityKey-per-relationship toward that peer (to sign Sig), or
// ok=false if no secret matches.
// claimSlot (nil = not enforced) enforces "one device per identity per
// room", called INSIDE the handshake, after ClientHello.Sig has already
// been verified (never before: only a peer that has already
// cryptographically proven possession of the IdentityKey-per-relationship
// can trigger an "occupied" rejection, otherwise an attacker with just a
// stolen secret, without the corresponding private key, could still
// discover whether that slot is occupied), BEFORE generating/sending
// ServerHello: a later rejection (e.g. in ws.go, after DoServerHandshake
// has already returned successfully) would always arrive too late, because
// DoClientHandshake has already received and verified ServerHello by then,
// considering the connection successful regardless of what the server does
// right after.
func DoServerHandshake(
	ctx context.Context,
	conn *websocket.Conn,
	secretLookup func(nonceClient, proof []byte) (secret []byte, roomID string, label string, identityPub []byte, devicePub []byte, peerKey shared.RelPeerKey, mySigningKey shared.RelSigningKey, ok bool),
	claimSlot func(roomID string, identityPub, devicePub []byte) bool,
) (shared.HandshakeResult, error) {
	reject := func(code shared.HandshakeErrorCode, msg string) (shared.HandshakeResult, error) {
		conn.Close(websocket.StatusPolicyViolation, string(code))
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_reject", code, msg))
	}

	// 1. receive ClientHello
	var hello shared.ClientHello
	if err := wsjson.Read(ctx, conn, &hello); err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_recv_client", err))
	}

	// 2. verify version
	if hello.Version != shared.HandshakeVersion {
		return reject(shared.ErrVersionMismatch, i18n.T("handshake.reject_version", hello.Version))
	}

	// 2b. verify ML-KEM-768 format (mandatory) and
	// encapsulate right away, a malformed payload with the correct version
	// is distinct from an actual version_mismatch, hence the dedicated
	// error code.
	if len(hello.MLKEMPub) != mlkem.EncapsulationKeySize768 {
		return reject(shared.ErrMissingHybridKEM, i18n.T("handshake.err_client_mlkem_required"))
	}
	mlkemEK, err := mlkem.NewEncapsulationKey768(hello.MLKEMPub)
	if err != nil {
		return reject(shared.ErrMissingHybridKEM, i18n.T("handshake.err_client_mlkem_required"))
	}
	mlkemSS, mlkemCiphertext := mlkemEK.Encapsulate()

	// 3. verify room_proof: look up the matching per-member secret, along
	// with the peer's IdentityKey-per-relationship (to verify Sig below)
	// and our own toward them (to sign ServerHello.Sig).
	matchedSecret, matchedRoomID, matchedLabel, matchedRootIdentityPub, matchedDevicePub, peerKey, mySigningKey, ok := secretLookup(hello.NonceClient, hello.RoomProof)
	if !ok {
		return reject(shared.ErrInvalidRoomProof, i18n.T("handshake.reject_room_proof"))
	}
	// Diagnostics: compares this pubkey (the one the host is about to sign
	// ServerHello.Sig with) against the one logged client-side
	// (DoClientHandshake, "verifying ServerHello with hostKey.Pub=...") to
	// tell apart an actual key mismatch from a problem elsewhere (payload,
	// transcript, MLDSA key).
	var mySigningPub ed25519.PublicKey
	if len(mySigningKey.Priv) == ed25519.PrivateKeySize {
		mySigningPub, _ = ed25519.PrivateKey(mySigningKey.Priv).Public().(ed25519.PublicKey)
	}
	dbg("handshake: label=%s peerKey.Pub=%s mySigningKey.Pub=%s", matchedLabel, base64.RawStdEncoding.EncodeToString(peerKey.Pub), base64.RawStdEncoding.EncodeToString(mySigningPub))

	// 4. verify Sig with the peer's IdentityKey-per-relationship, known
	// from the invite bootstrap (registered together with the secret),
	// never a global key or a fingerprint to resolve. SigMLDSA (if the peer
	// sends it) is verified additionally, never blocking if absent, same
	// principle as VerifyRemoteNukeMLDSA.
	if len(peerKey.Pub) != ed25519.PublicKeySize {
		return reject(shared.ErrUnknownIdentity, i18n.T("handshake.reject_unknown_identity"))
	}
	payload := shared.ClientSigPayload(hello.NonceClient, hello.SessionPub)
	if !ed25519.Verify(peerKey.Pub, payload, hello.Sig) {
		return reject(shared.ErrInvalidSignature, i18n.T("handshake.reject_bad_client_pub"))
	}
	if len(peerKey.MLDSAPub) > 0 && len(hello.SigMLDSA) > 0 {
		mldsaPub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(peerKey.MLDSAPub)
		if err == nil {
			if !mldsa65.Verify(mldsaPub.(*mldsa65.PublicKey), payload, nil, hello.SigMLDSA) {
				return reject(shared.ErrInvalidSignature, i18n.T("handshake.reject_bad_client_pub"))
			}
		}
	}

	// 4b. "one device per identity per room", see the comment on claimSlot
	// above for why this must happen here, not after DoServerHandshake has
	// already returned.
	if claimSlot != nil && !claimSlot(matchedRoomID, matchedRootIdentityPub, matchedDevicePub) {
		return reject(shared.ErrAlreadyConnected, i18n.T("handshake.reject_already_connected"))
	}

	// 4c. mySigningKey (OUR OWN IdentityKey-per-relationship toward this
	// peer) must be present to be able to sign ServerHello. Every real
	// caller already requires peerKey+mySigningKey together before
	// registering a secret, so this branch is never reached for a real
	// member; but without this explicit rejection the case would be
	// silently tolerated (ServerHello sent anyway, without Sig) and would
	// only fail later client-side, with a misleading diagnosis ("invalid
	// signature" instead of the real cause) after the server has already
	// done all the handshake work.
	if len(mySigningKey.Priv) != ed25519.PrivateKeySize {
		return reject(shared.ErrMissingSigningKey, i18n.T("handshake.reject_missing_signing_key"))
	}

	// 5. nonce_server + ephemeral X25519 pair
	nonceServer, err := shared.RandomBytes(32)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_nonce_server", err))
	}
	sessionPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_keygen", err))
	}
	sessionPubBytes := sessionPriv.PublicKey().Bytes()

	// 6. build ServerHello, signed with OUR OWN IdentityKey-per-
	// relationship toward this specific peer (mySigningKey, from
	// secretLookup), never a global key. mySigningKey.Priv already verified
	// valid at step 4c above: the signature here is unconditional, never
	// skipped.
	srvHello := shared.ServerHello{
		NonceServer:     nonceServer,
		SessionPub:      sessionPubBytes,
		MLKEMCiphertext: mlkemCiphertext,
	}
	srvPayload := shared.ServerSigPayload(hello.NonceClient, nonceServer, sessionPubBytes)
	srvHello.Sig = ed25519.Sign(mySigningKey.Priv, srvPayload)
	if len(mySigningKey.MLDSASeed) == mldsa65.SeedSize {
		var seed [mldsa65.SeedSize]byte
		copy(seed[:], mySigningKey.MLDSASeed)
		_, mldsaPriv := mldsa65.NewKeyFromSeed(&seed)
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(mldsaPriv, srvPayload, nil, true, sig); err == nil {
			srvHello.SigMLDSA = sig
		}
	}

	// 7. send ServerHello
	if err := wsjson.Write(ctx, conn, srvHello); err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_send_server", err))
	}

	// 8. X25519 DH + session key
	clientPub, err := ecdh.X25519().NewPublicKey(hello.SessionPub)
	if err != nil {
		return reject(shared.ErrInvalidSignature, i18n.T("handshake.reject_bad_client_pub"))
	}
	dhSecret, err := sessionPriv.ECDH(clientPub)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_ecdh", err))
	}
	sessionKey, err := shared.DeriveSessionKey(mlkemSS, dhSecret, hello.NonceClient, nonceServer, hello.SessionPub, sessionPubBytes)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_session_key", err))
	}

	return shared.HandshakeResult{
		SessionKey:             sessionKey,
		PeerUsername:           hello.Username,
		PeerECIESPub:           hello.ECIESPub,
		MatchedSecret:          matchedSecret,
		MatchedRoomID:          matchedRoomID,
		MatchedLabel:           matchedLabel,
		MatchedIdentityPub:     peerKey.Pub,
		MatchedRootIdentityPub: matchedRootIdentityPub,
		MatchedDevicePub:       matchedDevicePub,
		PeerMLKEMPub:           hello.MLKEMPub,
	}, nil
}
