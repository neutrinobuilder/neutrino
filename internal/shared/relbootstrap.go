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
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"encoding/json"
)

// RelBootstrapPayload is the point-to-point content exchanged between two
// room members with no prior direct relationship ("introduced") — each
// generates its own pair of EPHEMERAL relationship keys (valid only for
// this room) and sends the public part to the other over the same targeted
// channel already used for sender_key (to_user_id + payload, never a
// broadcast to the whole room). Pure TOFU: no certification against an
// external anchor, consistent with the lower trust tier already accepted
// for introduced members. Discarded when the room closes — never
// persisted, except on explicit promotion (see RelPromotePayload below).
type RelBootstrapPayload struct {
	IdentityPub      ed25519.PublicKey `json:"identity_pub"` // ephemeral IdentityKey-per-relationship (toward this peer, in this room)
	IdentityMLKEMPub []byte            `json:"identity_mlkem_pub,omitempty"`
	IdentityMLDSAPub []byte            `json:"identity_mldsa_pub,omitempty"`
	ContentPub       ed25519.PublicKey `json:"content_pub"` // ephemeral ContentKey-per-relationship (signs/encrypts messages toward this peer)
	ContentMLKEMPub  []byte            `json:"content_mlkem_pub,omitempty"`
	ContentMLDSAPub  []byte            `json:"content_mldsa_pub,omitempty"`

	// DevicePub — the SENDER's Ed25519 device pubkey (32 bytes,
	// keystore.Keystore.DevicePub), used ONLY when this payload travels
	// inside a KnockPayload.RelBootstrap (rel_init/rel_init_ack between real
	// contacts — see crypto.go) to key the correct
	// keystore.Contact.Devices entry on the receiving side. Empty and
	// ignored in the ephemeral in-room bootstrap (no per-device map there).
	// Field distinct from KnockPayload.DevicePub (that one signs the whole
	// knock for the TOFU of Contact.KnownDevicePub/remote_nuke — different
	// role, never reused here).
	DevicePub []byte `json:"device_pub,omitempty"`

	// Ts/Sig/SigMLDSA tie IdentityPub/ContentPub/DevicePub to the sender's
	// root IdentityKey — ONLY for the persistent channel (rel_init/
	// rel_init_ack via knock, KnockPayload.RelBootstrap): there, the two
	// sides already know and mutually trust each other's root IdentityKey
	// (exchanged out of band with the URI/QR), so the proposal can and must
	// be authenticated against that anchor — see RelBootstrapMsg/
	// SignRelBootstrap/VerifyRelBootstrap. Always empty in the ephemeral
	// in-room bootstrap (EncryptRelBootstrap/DecryptRelBootstrap above): two
	// "introduced" members have no common anchor to use, stays TOFU by
	// design (see the comment on the type, above). Sig is the Ed25519
	// signature of RelBootstrapMsg with the sender's root IdentityPrivKey —
	// mandatory in the persistent channel, a rel_init/rel_init_ack with no
	// valid signature is never applied. SigMLDSA is the parallel ML-DSA-65
	// counterpart, never blocking if absent (same treatment as the
	// project's other hybrid-PQC signatures).
	Ts       string `json:"ts,omitempty"`
	Sig      []byte `json:"sig,omitempty"`
	SigMLDSA []byte `json:"sig_mldsa,omitempty"`
}

// RelBootstrapMsg is the canonical signed message to authenticate a
// proposal of relationship keys (+ device) against the sender's root
// IdentityKey — ONLY the persistent rel_init/rel_init_ack channel, see the
// comment on RelBootstrapPayload.Ts/Sig/SigMLDSA above. ts is included in
// the signed message (not just the payload), same reason as
// RelKeyRotationMsg: without it, an attacker could rewrite ts on a captured
// payload without invalidating the signature.
// msg = "rel_bootstrap:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ identityPub ‖ contentPub ‖ devicePub
func RelBootstrapMsg(identityPub, contentPub, devicePub ed25519.PublicKey, username string, ts string) []byte {
	msg := append([]byte("rel_bootstrap:"+username+":"+ts+":"), identityPub...)
	msg = append(msg, contentPub...)
	msg = append(msg, devicePub...)
	return msg
}

// SignRelBootstrap signs RelBootstrapMsg with the sender's root
// IdentityPrivKey (Ed25519) — never with a relationship key, which at this
// point in the exchange isn't yet a trusted anchor for the recipient.
func SignRelBootstrap(rootPriv ed25519.PrivateKey, identityPub, contentPub, devicePub ed25519.PublicKey, username string, ts string) []byte {
	return ed25519.Sign(rootPriv, RelBootstrapMsg(identityPub, contentPub, devicePub, username, ts))
}

// VerifyRelBootstrap verifies SignRelBootstrap with the sender's root
// IdentityPub already known to the recipient (Contact.IdentityPub,
// exchanged out of band with the URI/QR) — never a relationship key.
func VerifyRelBootstrap(rootPub, identityPub, contentPub, devicePub ed25519.PublicKey, username string, ts string, sig []byte) bool {
	if len(rootPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(rootPub, RelBootstrapMsg(identityPub, contentPub, devicePub, username, ts), sig)
}

// SignRelBootstrapMLDSA/VerifyRelBootstrapMLDSA — parallel ML-DSA-65
// counterpart of SignRelBootstrap/VerifyRelBootstrap, never blocking if
// absent (one of the two parties doesn't yet have a known root MLDSAPub for
// the other), same scheme as
// SignRelKeyRotationMLDSA/VerifyRelKeyRotationMLDSA.
func SignRelBootstrapMLDSA(rootMLDSASeed []byte, identityPub, contentPub, devicePub ed25519.PublicKey, username string, ts string) []byte {
	priv := mldsaPrivFromSeed(rootMLDSASeed)
	if priv == nil {
		return nil
	}
	return mldsaSign(priv, RelBootstrapMsg(identityPub, contentPub, devicePub, username, ts))
}

func VerifyRelBootstrapMLDSA(rootMLDSAPubBytes []byte, identityPub, contentPub, devicePub ed25519.PublicKey, username string, ts string, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	pub := mldsaPubFromBytes(rootMLDSAPubBytes)
	if pub == nil {
		return false
	}
	return mldsaVerify(pub, RelBootstrapMsg(identityPub, contentPub, devicePub, username, ts), sig)
}

// RelPromotePayload is exchanged in addition to RelBootstrapPayload ONLY
// when two ephemeral members explicitly decide (human action, never
// automatic) to become real contacts — reuses the relationship keys already
// exchanged via RelBootstrapPayload, adds only what's missing to make the
// contact reachable outside this room: the transport address (public key
// that generates the onion/i2p address). Deliberately separate from
// RelBootstrapPayload: most strangers in a room will never be promoted, no
// point exposing a reachable network address to all of them from the
// ordinary bootstrap onward.
type RelPromotePayload struct {
	TransportPub      ed25519.PublicKey `json:"transport_pub"` // proposer's public Keystore.IdentityKey — generates their onion/i2p address
	TransportMLKEMPub []byte            `json:"transport_mlkem_pub,omitempty"`
	TransportMLDSAPub []byte            `json:"transport_mldsa_pub,omitempty"`

	// Ts/Sig/SigMLDSA tie TransportPub/TransportMLKEMPub/TransportMLDSAPub to
	// the EPHEMERAL IdentityKey-per-relationship already exchanged via
	// RelBootstrapPayload for this room — the only common anchor available
	// between two "introduced" members (no known root IdentityKey here,
	// unlike the persistent rel_init/rel_init_ack channel). Without this
	// signature, a malicious server — which already knows the recipient's
	// public session_pub, since it distributes it itself via
	// init/user_joined — could encrypt a fabricated RelPromotePayload and
	// inject it passing it off as a legitimate member's rel_promote,
	// redirecting a contact toward a transport address controlled by the
	// attacker, with neither sender nor recipient noticing. Sig is the Ed25519 signature of
	// RelPromoteMsg with the sender's EPHEMERAL IdentityKey-per-relationship
	// (ephemeralRel.myIdentity), verified by the recipient with
	// ephemeralRel.peerIdentity.Pub — THEIR half, already received and
	// applied from the preceding rel_bootstrap (Established==true, a
	// precondition already required to send/apply a rel_promote). SigMLDSA
	// is the parallel ML-DSA-65 counterpart, never blocking if absent. Sig
	// is mandatory: a rel_promote with no valid signature is never applied.
	Ts       string `json:"ts,omitempty"`
	Sig      []byte `json:"sig,omitempty"`
	SigMLDSA []byte `json:"sig_mldsa,omitempty"`
}

// RelPromoteMsg is the canonical signed message to authenticate a
// RelPromotePayload against the sender's EPHEMERAL
// IdentityKey-per-relationship — see the comment on
// RelPromotePayload.Ts/Sig/SigMLDSA. ts included in the signed message (not
// just the payload), same reason as RelBootstrapMsg: without it, an
// attacker could rewrite ts on a captured payload without invalidating the
// signature.
// msg = "rel_promote:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ transportPub ‖ transportMLKEMPub ‖ transportMLDSAPub
func RelPromoteMsg(transportPub ed25519.PublicKey, transportMLKEMPub, transportMLDSAPub []byte, username string, ts string) []byte {
	msg := append([]byte("rel_promote:"+username+":"+ts+":"), transportPub...)
	msg = append(msg, transportMLKEMPub...)
	msg = append(msg, transportMLDSAPub...)
	return msg
}

// SignRelPromote signs RelPromoteMsg with the sender's EPHEMERAL
// IdentityKey-per-relationship (ephemeralRel.myIdentity.Priv) — never the
// root IdentityKey, which at this point in the exchange doesn't exist as a
// common anchor ("introduced" members, no URI/QR exchanged out of band).
func SignRelPromote(ephemeralIdentityPriv ed25519.PrivateKey, transportPub ed25519.PublicKey, transportMLKEMPub, transportMLDSAPub []byte, username string, ts string) []byte {
	return ed25519.Sign(ephemeralIdentityPriv, RelPromoteMsg(transportPub, transportMLKEMPub, transportMLDSAPub, username, ts))
}

// VerifyRelPromote verifies SignRelPromote with the peer's EPHEMERAL
// IdentityKey-per-relationship already known to the recipient
// (ephemeralRel.peerIdentity.Pub, received from the preceding
// rel_bootstrap) — never the root IdentityKey.
func VerifyRelPromote(ephemeralIdentityPub, transportPub ed25519.PublicKey, transportMLKEMPub, transportMLDSAPub []byte, username string, ts string, sig []byte) bool {
	if len(ephemeralIdentityPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ephemeralIdentityPub, RelPromoteMsg(transportPub, transportMLKEMPub, transportMLDSAPub, username, ts), sig)
}

// SignRelPromoteMLDSA/VerifyRelPromoteMLDSA — parallel ML-DSA-65
// counterpart of SignRelPromote/VerifyRelPromote, never blocking if absent,
// same scheme as SignRelBootstrapMLDSA/VerifyRelBootstrapMLDSA.
func SignRelPromoteMLDSA(ephemeralIdentityMLDSASeed []byte, transportPub ed25519.PublicKey, transportMLKEMPub, transportMLDSAPub []byte, username string, ts string) []byte {
	priv := mldsaPrivFromSeed(ephemeralIdentityMLDSASeed)
	if priv == nil {
		return nil
	}
	return mldsaSign(priv, RelPromoteMsg(transportPub, transportMLKEMPub, transportMLDSAPub, username, ts))
}

func VerifyRelPromoteMLDSA(ephemeralIdentityMLDSAPubBytes []byte, transportPub ed25519.PublicKey, transportMLKEMPub, transportMLDSAPub []byte, username string, ts string, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	pub := mldsaPubFromBytes(ephemeralIdentityMLDSAPubBytes)
	if pub == nil {
		return false
	}
	return mldsaVerify(pub, RelPromoteMsg(transportPub, transportMLKEMPub, transportMLDSAPub, username, ts), sig)
}

// EncryptRelBootstrap encrypts p toward the recipient's ephemeral session
// (SessionPub/MLKEMPub, known from the init/user_joined relay —
// per-session values, not correlatable across different rooms). Same
// hybrid scheme already used for sender_key.
func EncryptRelBootstrap(recipientSessionPub *ecdh.PublicKey, recipientMLKEMPub *mlkem.EncapsulationKey768, p RelBootstrapPayload) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return HybridECIESEncrypt(recipientSessionPub, recipientMLKEMPub, data)
}

// DecryptRelBootstrap decrypts a payload produced by EncryptRelBootstrap.
func DecryptRelBootstrap(mySessionPriv *ecdh.PrivateKey, myMLKEMPriv *mlkem.DecapsulationKey768, payload string) (RelBootstrapPayload, error) {
	data, err := HybridECIESDecrypt(mySessionPriv, myMLKEMPriv, payload)
	if err != nil {
		return RelBootstrapPayload{}, err
	}
	var p RelBootstrapPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return RelBootstrapPayload{}, err
	}
	return p, nil
}

// EncryptRelPromote/DecryptRelPromote: same scheme as
// EncryptRelBootstrap/DecryptRelBootstrap, for RelPromotePayload.
func EncryptRelPromote(recipientSessionPub *ecdh.PublicKey, recipientMLKEMPub *mlkem.EncapsulationKey768, p RelPromotePayload) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return HybridECIESEncrypt(recipientSessionPub, recipientMLKEMPub, data)
}

func DecryptRelPromote(mySessionPriv *ecdh.PrivateKey, myMLKEMPriv *mlkem.DecapsulationKey768, payload string) (RelPromotePayload, error) {
	data, err := HybridECIESDecrypt(mySessionPriv, myMLKEMPriv, payload)
	if err != nil {
		return RelPromotePayload{}, err
	}
	var p RelPromotePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return RelPromotePayload{}, err
	}
	return p, nil
}
