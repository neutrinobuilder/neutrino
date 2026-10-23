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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"
)

// I2P "destination" format for SigningKeyType=EdDSA_SHA512_Ed25519(7) +
// CryptoKeyType=ECIES_X25519_AEAD(4), as defined by libi2pd/Identity.h and
// Identity.cpp (i2pd):
//
//	public (391 bytes):
//	  publicKey[256]:  X25519 pub (32B, offset 0) + padding (224B, ignored)
//	  signingKey[128]: padding (96B, ignored) + Ed25519 pub (32B, offset 96-127)
//	  certificate[3]:  0x05 (KeyCertificate) + uint16be(4)
//	  extended[4]:     uint16be(7) + uint16be(4)
//	private (+64 bytes after the public part): private X25519 scalar (32B) + Ed25519 seed (32B)
const (
	i2pSignatureTypeEdDSA    = 7
	i2pCryptoTypeECIESX25519 = 4
	i2pDestinationPubLen     = 391
)

// I2PDestinationPub builds the public I2P "destination" blob (391 bytes) for
// pub — computable by anyone who knows only the contact's Ed25519 public
// key, same property as OnionAddressFromPub. The X25519 encryption key is
// derived from pub via the standard birational map between the
// Edwards25519 and Curve25519 curves (same technique as libsodium's
// crypto_sign_ed25519_pk_to_curve25519), not from a secret — which is why
// it's computable even by someone who doesn't hold the private key.
func I2PDestinationPub(pub ed25519.PublicKey) ([]byte, error) {
	x25519Pub, err := i2pX25519PubFromEd25519Pub(pub)
	if err != nil {
		return nil, err
	}
	return i2pBuildDestinationPub(pub, x25519Pub), nil
}

// I2PDestinationPriv builds the complete private "destination" blob (455
// bytes: 391 public + private X25519 scalar + Ed25519 seed), ready for
// "SESSION CREATE ... DESTINATION=<base64>" over SAM. The private X25519 key
// is derived from priv.Seed() with the same hash+clamp Ed25519 already
// computes internally from its own seed (RFC 8032 §5.1.5): no new secret, no
// change to the keystore schema.
func I2PDestinationPriv(priv ed25519.PrivateKey) ([]byte, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pubBlob, err := I2PDestinationPub(pub)
	if err != nil {
		return nil, err
	}
	x25519Priv := i2pX25519PrivFromEd25519Seed(priv.Seed())
	out := make([]byte, 0, i2pDestinationPubLen+32+32)
	out = append(out, pubBlob...)
	out = append(out, x25519Priv...)
	out = append(out, priv.Seed()...)
	return out, nil
}

// I2PAddress computes the .b32.i2p address for priv. Analogous to OnionAddress.
func I2PAddress(priv ed25519.PrivateKey) (string, error) {
	return I2PAddressFromPub(priv.Public().(ed25519.PublicKey))
}

// I2PAddressFromPub computes the .b32.i2p address from only a contact's
// Ed25519 public key. Analogous to OnionAddressFromPub.
func I2PAddressFromPub(pub ed25519.PublicKey) (string, error) {
	dest, err := I2PDestinationPub(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(dest)
	addr := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])
	return strings.ToLower(addr) + ".b32.i2p", nil
}

// i2pX25519PubFromEd25519Pub converts an Ed25519 public key (compressed
// Edwards point) into the corresponding X25519 public key (Montgomery
// u-coordinate) via the birational map between the two curves.
func i2pX25519PubFromEd25519Pub(pub ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("i2p: invalid Ed25519 key: %w", err)
	}
	return p.BytesMontgomery(), nil
}

// i2pX25519PrivFromEd25519Seed derives the private X25519 scalar from the
// Ed25519 seed: same hash+clamp Ed25519 already uses internally to compute
// its own signing scalar, so the resulting public point exactly matches
// i2pX25519PubFromEd25519Pub computed on the corresponding public key.
func i2pX25519PrivFromEd25519Seed(seed []byte) []byte {
	h := sha512.Sum512(seed)
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return scalar
}

// i2pPadding generates the filler bytes (320 = 224+96) for the
// publicKey/signingKey fields of the destination blob. Derived from pub
// (public, not a secret) via HKDF so they're deterministic — random padding
// that differed on every call would change the .b32.i2p address on every
// reconstruction, breaking the stability this whole derivation is meant to
// guarantee — and indistinguishable from random bytes (unlike zero padding,
// which would be a recognizable pattern as "not generated by a real i2pd" on
// the I2P network).
func i2pPadding(pub ed25519.PublicKey) []byte {
	r := hkdf.New(sha256.New, pub, nil, []byte("neutrino-i2p-padding-v1"))
	out := make([]byte, 224+96)
	io.ReadFull(r, out) //nolint:errcheck // hkdf.Read on a freshly created reader never fails
	return out
}

func i2pBuildDestinationPub(edPub ed25519.PublicKey, x25519Pub []byte) []byte {
	padding := i2pPadding(edPub)
	buf := make([]byte, i2pDestinationPubLen)
	copy(buf[0:32], x25519Pub)
	copy(buf[32:256], padding[0:224])
	copy(buf[256:256+96], padding[224:320])
	copy(buf[256+96:256+128], edPub)
	buf[384] = 5 // CERTIFICATE_TYPE_KEY
	binary.BigEndian.PutUint16(buf[385:387], 4)
	binary.BigEndian.PutUint16(buf[387:389], i2pSignatureTypeEdDSA)
	binary.BigEndian.PutUint16(buf[389:391], i2pCryptoTypeECIESX25519)
	return buf
}
