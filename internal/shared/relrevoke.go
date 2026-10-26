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

import "crypto/ed25519"

// RelRevokeMsg is the SELF-SIGNED message that revokes a specific instance
// of a relationship key (RelIdentityKey or RelContentKey) toward a contact,
// same principle as a PGP revocation certificate: the private key signs its
// own public key, generated once together with the key itself (bootstrap or
// rotation), not at the moment it would actually be needed. This makes it
// available even after the private key disappears forever (nuke).
// username ties the revocation to that specific relationship (same
// defensive principle already used in RelKeyRotationMsg, relationship keys
// are already unique per contact regardless, so a cross-replay isn't
// possible anyway). No timestamp: a replay of a revocation is always
// harmless, never a trust escalation, forces at most a reconfirmation via
// TrustDanger, never a security downgrade.
// msg = "rel_revoke:" ‖ username ‖ ":" ‖ pub
func RelRevokeMsg(pub ed25519.PublicKey, username string) []byte {
	return append([]byte("rel_revoke:"+username+":"), pub...)
}

// SignRelRevoke self-signs pub (derived from priv) with priv itself, priv
// is the current RelIdentityPriv or RelContentPriv toward that contact, pub
// is its public counterpart (the one the contact already knows as
// PeerRelIdentityPub/PeerRelContentPub).
func SignRelRevoke(priv ed25519.PrivateKey, username string) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	return ed25519.Sign(priv, RelRevokeMsg(pub, username))
}

// VerifyRelRevoke verifies a received revocation against the already-known
// relationship public key (PeerRelIdentityPub/PeerRelContentPub). If it
// doesn't verify, because the known key has since changed due to a
// subsequent rotation, the revocation is simply inert, never dangerous: it
// never downgrades to "not revoked" a state already set elsewhere.
func VerifyRelRevoke(pub ed25519.PublicKey, username string, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) == 0 {
		return false
	}
	return ed25519.Verify(pub, RelRevokeMsg(pub, username), sig)
}

// SignRelRevokeMLDSA/VerifyRelRevokeMLDSA, parallel ML-DSA-65 signature,
// same principle as the project's other parallel PQC signatures: never
// blocking if absent on the verifying side (one of the two parties doesn't
// yet have an ML-DSA companion for that relationship key).
func SignRelRevokeMLDSA(mldsaSeed []byte, pub ed25519.PublicKey, username string) []byte {
	priv := mldsaPrivFromSeed(mldsaSeed)
	if priv == nil {
		return nil
	}
	return mldsaSign(priv, RelRevokeMsg(pub, username))
}

func VerifyRelRevokeMLDSA(mldsaPubBytes []byte, pub ed25519.PublicKey, username string, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	mpub := mldsaPubFromBytes(mldsaPubBytes)
	if mpub == nil {
		return false
	}
	return mldsaVerify(mpub, RelRevokeMsg(pub, username), sig)
}

// RelRevokePayload travels inside KnockPayload.RelRevoke, Type "rel_revoke"
// (announcement) / "rel_revoke_ack" (confirmation, fire-and-forget).
// Presents the recipient with self-revocation certificates already prepared
// long before (see above), never generated on the spot: whoever sends them
// can be either the device directly concerned or a sibling acting as a
// backstop on its behalf (keystore.Contact.SiblingRevocations),
// indistinguishable to the recipient, who only verifies the signature
// against the already-known relationship key, never the identity of whoever
// actually sent the knock.
//
// No timestamp (unlike RelRotatePayload/RootRotatePayload): a replay is
// always harmless, never a trust escalation, see the comment on
// RelRevokeMsg above.
type RelRevokePayload struct {
	// DevicePub identifies THE DEVICE whose relationship is being revoked,
	// same meaning as RelRotatePayload.DevicePub/RelBootstrapPayload.DevicePub
	// (Keystore.DevicePub, 32 bytes): keys the correct
	// keystore.Contact.Devices entry on the receiving side. NEVER the device
	// of whoever materially sent the knock, when a sibling acts as backstop.
	DevicePub []byte `json:"device_pub"`

	// IdentitySig/ContentSig are the self-revocation certificates, at
	// least one of the two is always present in a valid announcement, never
	// both absent (a device can revoke only the IdentityKey, only the
	// ContentKey, or both in the same knock). Absent in the ack (echo with
	// no signatures, only DevicePub set to disambiguate which revocation is
	// being confirmed).
	IdentitySig      []byte `json:"identity_sig,omitempty"`
	IdentitySigMLDSA []byte `json:"identity_sig_mldsa,omitempty"`
	ContentSig       []byte `json:"content_sig,omitempty"`
	ContentSigMLDSA  []byte `json:"content_sig_mldsa,omitempty"`
}
