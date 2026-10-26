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
	"crypto/rand"
	"testing"
)

// TestRelPromoteSignVerify covers SignRelPromote/VerifyRelPromote, the
// signature that ties RelPromotePayload to the sender's EPHEMERAL
// IdentityKey-per-relationship (see the comment on
// RelPromotePayload.Ts/Sig/SigMLDSA), same principle as
// SignRelBootstrap/VerifyRelBootstrap but with the ephemeral anchor instead
// of the root IdentityKey. Without this signature, a malicious server could
// inject a fabricated transport address passing it off as a legitimate
// member's rel_promote.
func TestRelPromoteSignVerify(t *testing.T) {
	ephemeralPub, ephemeralPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	transportPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	transportMLKEMPub := []byte{1, 2, 3}
	transportMLDSAPub := []byte{4, 5, 6}
	username := "alice"

	t.Run("valid signature is accepted", func(t *testing.T) {
		ts := NowTS()
		sig := SignRelPromote(ephemeralPriv, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts)
		if !VerifyRelPromote(ephemeralPub, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts, sig) {
			t.Fatal("a valid signature was refused")
		}
	})

	t.Run("signature with the wrong key is refused", func(t *testing.T) {
		ts := NowTS()
		sig := SignRelPromote(wrongPriv, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts)
		if VerifyRelPromote(ephemeralPub, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts, sig) {
			t.Fatal("a signature computed with the wrong key was accepted")
		}
	})

	t.Run("missing sig is refused", func(t *testing.T) {
		ts := NowTS()
		if VerifyRelPromote(ephemeralPub, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts, nil) {
			t.Fatal("a missing signature was accepted")
		}
	})

	t.Run("tampering with transportPub after signing is detected", func(t *testing.T) {
		ts := NowTS()
		sig := SignRelPromote(ephemeralPriv, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts)
		tamperedPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyRelPromote(ephemeralPub, tamperedPub, transportMLKEMPub, transportMLDSAPub, username, ts, sig) {
			t.Fatal("a transportPub tampered with after signing was accepted")
		}
	})

	t.Run("rewriting ts after signing is detected", func(t *testing.T) {
		ts := NowTS()
		sig := SignRelPromote(ephemeralPriv, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts)
		if VerifyRelPromote(ephemeralPub, transportPub, transportMLKEMPub, transportMLDSAPub, username, "9999999999", sig) {
			t.Fatal("a ts rewritten after signing was accepted")
		}
	})

	t.Run("wrong username is detected", func(t *testing.T) {
		ts := NowTS()
		sig := SignRelPromote(ephemeralPriv, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts)
		if VerifyRelPromote(ephemeralPub, transportPub, transportMLKEMPub, transportMLDSAPub, "mallory", ts, sig) {
			t.Fatal("a signature verified against a username different from the signed one was accepted")
		}
	})
}

// TestRelPromoteSignVerifyMLDSA covers the parallel ML-DSA-65 counterpart.
// mldsaPub here plays the role of ephemeralRel.peerIdentity.MLDSAPub on the
// verifying side, the public companion of the seed used to sign, unrelated
// to the arbitrary transport* values used as the signed message's content.
func TestRelPromoteSignVerifyMLDSA(t *testing.T) {
	key, err := GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, _, mldsaPub, err := RelSigningKeyPublicParts(key)
	if err != nil {
		t.Fatal(err)
	}
	transportPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	transportMLKEMPub := []byte{1, 2, 3}
	transportMLDSAPub := []byte{4, 5, 6}
	username := "alice"

	t.Run("valid MLDSA signature is accepted", func(t *testing.T) {
		ts := NowTS()
		sig := SignRelPromoteMLDSA(key.MLDSASeed, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts)
		if sig == nil {
			t.Fatal("SignRelPromoteMLDSA returned nil with a valid seed")
		}
		if !VerifyRelPromoteMLDSA(mldsaPub, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts, sig) {
			t.Fatal("a valid MLDSA signature was refused")
		}
	})

	t.Run("MLDSA signature with the wrong key is refused", func(t *testing.T) {
		ts := NowTS()
		sig := SignRelPromoteMLDSA(wrongKey.MLDSASeed, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts)
		if VerifyRelPromoteMLDSA(mldsaPub, transportPub, transportMLKEMPub, transportMLDSAPub, username, ts, sig) {
			t.Fatal("an MLDSA signature computed with the wrong seed was accepted")
		}
	})
}
