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

package shared

import (
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ErrInvalidRelSigningKey: RelSigningKeyPublicParts called on a key with no
// Ed25519 part (empty Priv), no point deriving its public parts.
var ErrInvalidRelSigningKey = errors.New("rel signing key: missing Ed25519 priv")

// RelSigningKey is the IdentityKey-per-relationship (+ PQC companions) that
// a server's owner will use to sign ServerHello.Sig when the secret
// associated with a member matches, the relationship key specific to that
// member, never a global key.
type RelSigningKey struct {
	Priv      ed25519.PrivateKey
	MLKEMSeed []byte
	MLDSASeed []byte
}

// RelPeerKey is the PEER's IdentityKey-per-relationship (+ optional ML-DSA-65
// companion, never blocking if absent) used to verify Sig/SigMLDSA, known
// by whoever distributes/receives a secret from the invite bootstrap onward.
type RelPeerKey struct {
	Pub      ed25519.PublicKey
	MLDSAPub []byte
}

// GenerateRelSigningKey generates a new, random, independent relationship
// key pair, Ed25519 + the two PQC companions (ML-KEM-768, ML-DSA-65). Same
// trio used both for persistent relationship keys
// (Contact.RelIdentityPriv/RelContentPriv) and for the ephemeral ones in the
// point-to-point bootstrap between "introduced" members (never persisted in
// that case, see RelBootstrapPayload).
func GenerateRelSigningKey() (RelSigningKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return RelSigningKey{}, err
	}
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return RelSigningKey{}, err
	}
	mldsaSeed := make([]byte, mldsa65.SeedSize)
	if _, err := rand.Read(mldsaSeed); err != nil {
		return RelSigningKey{}, err
	}
	return RelSigningKey{Priv: priv, MLKEMSeed: mlkemDK.Bytes(), MLDSASeed: mldsaSeed}, nil
}

// RelSigningKeyPublicParts derives the three public parts (Ed25519,
// ML-KEM-768, ML-DSA-65) from a RelSigningKey, used to build the public
// payload sent to the other party (RelBootstrapPayload/RelPromotePayload)
// or to populate the Peer* fields of a promoted Contact. mlkemPub/mldsaPub
// are nil if the respective seed is absent or malformed (never a blocking
// error: the same fields on the payload are omitempty).
func RelSigningKeyPublicParts(k RelSigningKey) (edPub ed25519.PublicKey, mlkemPub []byte, mldsaPub []byte, err error) {
	if len(k.Priv) != ed25519.PrivateKeySize {
		return nil, nil, nil, ErrInvalidRelSigningKey
	}
	edPub = k.Priv.Public().(ed25519.PublicKey)
	if len(k.MLKEMSeed) > 0 {
		mlkemDK, derr := mlkem.NewDecapsulationKey768(k.MLKEMSeed)
		if derr == nil {
			mlkemPub = mlkemDK.EncapsulationKey().Bytes()
		}
	}
	if len(k.MLDSASeed) == mldsa65.SeedSize {
		var seed [mldsa65.SeedSize]byte
		copy(seed[:], k.MLDSASeed)
		pub, _ := mldsa65.NewKeyFromSeed(&seed)
		mldsaPub = pub.Bytes()
	}
	return edPub, mlkemPub, mldsaPub, nil
}

// HandshakeVersion is the current version of the handshake protocol. A
// peer with any other version is rejected explicitly and immediately (no
// permissive policy). Version 5: per-member secret (RoomRegistry indexed
// by roomID); mandatory hybrid X25519+ML-KEM-768 key exchange
// (ClientHello.MLKEMPub, ServerHello.MLKEMCiphertext); Sig signs with the
// IdentityKey-per-relationship (known by both sides from the invite
// bootstrap onward, never a global key); no field declares an identity on
// the wire (the ContentKey-per-relationship is never declared on the wire
// for a direct contact it's already known by both sides, for an unknown
// party introduced in a room it's exchanged point-to-point outside the
// handshake).
const HandshakeVersion = 5

// HandshakeErrorCode is the error code sent by the server before closing the WebSocket.
type HandshakeErrorCode string

const (
	ErrInvalidRoomProof    HandshakeErrorCode = "invalid_room_proof"
	ErrUnknownIdentity     HandshakeErrorCode = "unknown_identity"
	ErrInvalidSignature    HandshakeErrorCode = "invalid_signature"
	ErrWrongServerIdentity HandshakeErrorCode = "wrong_server_identity"
	ErrVersionMismatch     HandshakeErrorCode = "version_mismatch"
	ErrPeriodExpired       HandshakeErrorCode = "period_expired"
	// ErrMissingHybridKEM: HandshakeVersion matches but the expected
	// ML-KEM-768 field is absent or of the wrong length, malformed
	// payload, distinct from an actual version_mismatch (where the version
	// itself doesn't match).
	ErrMissingHybridKEM HandshakeErrorCode = "missing_hybrid_kem"
	// ErrAlreadyConnected: a DIFFERENT device of the same identity (root
	// IdentityPub) is already connected to this room, "one device per
	// identity per room". Different from all the other codes above: not a
	// failure of the cryptographic handshake itself (arrives AFTER
	// ClientHello.Sig has already been successfully verified), but a
	// room-level rejection, still reuses the same WS close mechanism
	// (StatusPolicyViolation + this code as reason) for consistency with
	// the others, and because the client must be able to distinguish it the
	// same exact way (see client.ErrAlreadyConnectedElsewhere).
	ErrAlreadyConnected HandshakeErrorCode = "already_connected"
	// ErrMissingSigningKey: peerKey (the client's IdentityKey-per-relationship)
	// is known and has already passed Sig verification, but mySigningKey
	// (the OWN IdentityKey-per-relationship toward this specific peer) is
	// absent, the server could not sign ServerHello. Every real caller
	// requires peerKey+mySigningKey together before registering a
	// secret (AddSecret/ReplaceSecret), so this branch is never reached for
	// a real member, but a ServerHello sent anyway, without Sig, would be
	// rejected client-side (an empty signature never verifies) with a
	// misleading diagnosis ("invalid signature" instead of "the server has
	// no key to sign toward you") and only after the server has already
	// done all the handshake work. Explicit rejection here, instead of
	// silent tolerance.
	ErrMissingSigningKey HandshakeErrorCode = "missing_signing_key"
)

// ClientHello is the first WebSocket message sent by the client.
//
// Sig proves possession of the IdentityKey-per-relationship dedicated to
// this specific peer, key generated at random at invite/bootstrap time,
// independent per contact, never global. Whoever receives it verifies
// against the IdentityKey-per-relationship already known from the bootstrap
// (registered together with the secret at invite time,
// RoomRegistry.AddSecret), no fingerprint to resolve, no cache, no network
// fetch: the verification key is already in the hands of whoever needs it,
// by construction.
type ClientHello struct {
	Version     int    `json:"version"`
	NonceClient []byte `json:"nonce_client"` // 32 random bytes
	SessionPub  []byte `json:"session_pub"`  // ephemeral X25519 for ECDH handshake
	// MLKEMPub is the ephemeral ML-KEM-768 encapsulation key (1184 bytes),
	// generated on every connection like SessionPub, mandatory. The server
	// uses it for Encapsulate() and replies with ServerHello.MLKEMCiphertext;
	// the resulting shared secret combines with the X25519 one in
	// DeriveSessionKey.
	MLKEMPub  []byte `json:"mlkem_pub"`
	RoomProof []byte `json:"room_proof"`          // HMAC-SHA256(room_key, nonce_client)
	Username  string `json:"username"`            // display name in the room
	ECIESPub  string `json:"ecies_pub"`           // base64 X25519, public key for peer-to-peer ECIES
	Sig       []byte `json:"sig,omitempty"`       // Ed25519 signature (IdentityKey-per-relationship) over (nonce_client || session_pub)
	SigMLDSA  []byte `json:"sig_mldsa,omitempty"` // parallel ML-DSA-65 signature of the same payload, hybrid PQC, same principle already used for SignRemoteNukeMLDSA
}

// ServerHello is the server's reply to ClientHello. Sig/SigMLDSA: same
// principle as ClientHello.Sig/SigMLDSA above, signed with the
// IdentityKey-per-relationship (+ ML-DSA companion) the host uses toward
// THIS specific client.
type ServerHello struct {
	NonceServer []byte `json:"nonce_server"` // 32 random bytes
	SessionPub  []byte `json:"session_pub"`  // X25519 pubkey, 32 bytes
	// MLKEMCiphertext is the ML-KEM-768 ciphertext (1088 bytes) produced by
	// Encapsulate() against ClientHello.MLKEMPub, mandatory, see the
	// comment on ClientHello.MLKEMPub.
	MLKEMCiphertext []byte `json:"mlkem_ciphertext"`
	Sig             []byte `json:"sig,omitempty"`       // Ed25519 signature over (nonce_client || nonce_server || session_pub)
	SigMLDSA        []byte `json:"sig_mldsa,omitempty"` // parallel ML-DSA-65 signature
}

// HandshakeResult contains everything needed after a successful handshake.
//
// The IdentityKey-per-relationship is always required (no permissive
// policy): a handshake that gets as far as returning a HandshakeResult has
// always verified Sig against it, no separate field is needed to
// distinguish it.
type HandshakeResult struct {
	SessionKey    []byte // 32 bytes, AES-256-GCM key for the channel
	PeerUsername  string // username declared by the client
	PeerECIESPub  string // base64 X25519, peer's ECIES public key (for sender key)
	MatchedSecret []byte // specific (per-member) secret that authenticated this connection
	MatchedRoomID string // room the matched secret belongs to, stable identity, independent of the secret
	MatchedLabel  string // username assigned by whoever distributed the secret, overrides PeerUsername if non-empty
	// MatchedIdentityPub is the durable IdentityKey-per-relationship
	// associated with the matched secret, known by whoever distributed the
	// secret (registered at invite time, RoomRegistry.AddSecret), not
	// declared by the client itself in ClientHello. Never relayed to
	// already-connected members (it would expose to the whole room data
	// that should stay known only to the host): for the host's exclusive
	// use to recognize/reach that member.
	MatchedIdentityPub []byte
	// MatchedRootIdentityPub is the contact's STABLE (root) IdentityPub,
	// never the one that rotates, unlike MatchedIdentityPub above (which is
	// the peer's RelIdentityPub, which changes on every rotation). Used to enforce
	// "one device per identity per room" (RoomRegistry.ClaimIdentitySlot),
	// nil for a caller that doesn't know it yet (no enforcement possible in
	// that case, never a rejection).
	MatchedRootIdentityPub []byte
	// MatchedDevicePub is the peer's DevicePub associated with the matched
	// secret (same field as memberSecret.devicePub), nil if unknown.
	// Together with MatchedRootIdentityPub it identifies EXACTLY which
	// device of which identity is connecting, distinguishing a genuine
	// reconnection (same device, new session) from a DIFFERENT device of
	// the same identity trying to occupy the same slot.
	MatchedDevicePub []byte
	// PeerMLKEMPub is the ephemeral ML-KEM-768 encapsulation key declared by
	// the client in this handshake (ClientHello.MLKEMPub), reused by the
	// server to relay it to already-connected room members
	// (wsUserJoined/userInfo, same scheme already used for PeerECIESPub) so
	// the peer-to-peer delivery of sender_key can become hybrid without
	// generating a second key pair.
	PeerMLKEMPub []byte
	// ClientMLKEMDecap is the ML-KEM-768 decapsulation key generated by
	// DoClientHandshake for THIS connection, populated ONLY client-side
	// (nil when the result comes from DoServerHandshake, which generates no
	// key of its own to expose here). The client keeps it for the whole
	// connection to decapsulate the hybrid sender_key payloads that peers
	// encrypt toward the same MLKEMPub already announced in the handshake,
	// safe by construction, an ML-KEM encapsulation key can receive
	// Encapsulate() from multiple independent parties (here: the server for
	// the session_key, and each peer for their own sender_key) with no loss
	// of security.
	ClientMLKEMDecap *mlkem.DecapsulationKey768
}
