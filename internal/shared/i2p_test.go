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
	"bytes"
	"crypto/ed25519"
	"testing"
)

// TestI2PDestinationDeterministic verifies that independent constructions
// from the same key produce the same blob (and therefore the same address)
// — a version with random padding would make the address change on every
// call.
func TestI2PDestinationDeterministic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	b1, err := I2PDestinationPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := I2PDestinationPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("I2PDestinationPub is not deterministic")
	}
	if len(b1) != i2pDestinationPubLen {
		t.Fatalf("public blob length: want %d, got %d", i2pDestinationPubLen, len(b1))
	}

	privBlob, err := I2PDestinationPriv(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(privBlob) != i2pDestinationPubLen+32+32 {
		t.Fatalf("private blob length: want %d, got %d", i2pDestinationPubLen+32+32, len(privBlob))
	}
	if !bytes.Equal(privBlob[:i2pDestinationPubLen], b1) {
		t.Fatal("the private blob's public part doesn't match I2PDestinationPub")
	}

	addr1, err := I2PAddressFromPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := I2PAddress(priv)
	if err != nil {
		t.Fatal(err)
	}
	if addr1 != addr2 {
		t.Fatalf("I2PAddressFromPub and I2PAddress diverge: %q vs %q", addr1, addr2)
	}
	if len(addr1) == 0 {
		t.Fatal("empty address")
	}
}

// TestI2PDestinationPublicDerivability verifies the central property of the
// design: a contact who knows only the Ed25519 public key (never the
// private one) must be able to compute the same .b32.i2p address that the
// identity's owner computes from their own private key — same property as
// OnionAddressFromPub for Tor.
func TestI2PDestinationPublicDerivability(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	ownAddr, err := I2PAddress(priv)
	if err != nil {
		t.Fatal(err)
	}
	contactAddr, err := I2PAddressFromPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	if ownAddr != contactAddr {
		t.Fatalf("address computed by the owner (%q) differs from the one computed by a contact with only the public key (%q)", ownAddr, contactAddr)
	}
}

// TestI2PDestinationDifferentKeysDifferentAddresses is a minimal sanity
// check: different keys must produce different addresses.
func TestI2PDestinationDifferentKeysDifferentAddresses(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	addr1, err := I2PAddressFromPub(pub1)
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := I2PAddressFromPub(pub2)
	if err != nil {
		t.Fatal(err)
	}
	if addr1 == addr2 {
		t.Fatal("different keys produced the same address")
	}
}
