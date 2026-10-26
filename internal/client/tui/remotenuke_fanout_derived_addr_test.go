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

package tui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// TestRemoteNukeFanOutTriesDerivedAddressForOwnIdentity verifies the
// remote_nuke fan-out: a device listed in KnownDevices by definition hosts
// THIS identity (SiblingIdentityRefs always includes itself), but if it
// hosts it as an ADDITIONAL device (not D1) its real address is the one
// derived via Keystore.NetworkIdentityPrivKeyFor(targetDeviceID), not
// OnionAddressFromPub applied directly to the root IdentityPub. For a
// target whose IdentityPub matches our own, BOTH candidate addresses (root
// and derived) must be tried, never one in place of the other.
func TestRemoteNukeFanOutTriesDerivedAddressForOwnIdentity(t *testing.T) {
	myPub, myPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	derivedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetDeviceID := []byte{9, 9, 9, 9}

	var dialedMu sync.Mutex
	var dialed []string
	dial := func(_ context.Context, _ string, addr string) (net.Conn, error) {
		dialedMu.Lock()
		dialed = append(dialed, addr)
		dialedMu.Unlock()
		return nil, errFakeDialRefused
	}

	m := &model{
		remoteNukeCancels: make(map[string]*remoteNukeEntry),
		remoteNukeMu:      &sync.Mutex{},
		myIdentityPub:     myPub,
		dialTor:           dial,
		knockHttpTimeout:  50 * time.Millisecond,
		knockRetryDelay:   0,
		dhTagFn: func(ed25519.PublicKey) ([]byte, error) {
			return []byte("tag"), nil
		},
		signRemoteNuke: func(targetDeviceID []byte, ts string) []byte {
			return []byte("sig")
		},
		addressFromPub: func(pub ed25519.PublicKey) string {
			switch {
			case bytes.Equal(pub, myPub):
				return "root-addr.onion"
			case bytes.Equal(pub, derivedPub):
				return "derived-addr.onion"
			default:
				return ""
			}
		},
		networkIdentityPubFor: func(deviceID []byte) ed25519.PublicKey {
			if !bytes.Equal(deviceID, targetDeviceID) {
				t.Errorf("networkIdentityPubFor called with the wrong targetDeviceID: %x", deviceID)
			}
			return derivedPub
		},
	}
	_ = myPriv

	rec := DeviceRecordInfo{
		DeviceID: targetDeviceID,
		SiblingIdentities: []DeviceIdentityRef{
			{Username: m.myUsername, IdentityPub: myPub},
		},
	}

	cmd := m.cmdRemoteNukeFanOut(rec)
	if cmd == nil {
		t.Fatal("cmdRemoteNukeFanOut: want a non-nil tea.Cmd")
	}
	cmd() // synchronous: dial fails right away, no real network I/O

	dialedMu.Lock()
	defer dialedMu.Unlock()
	sawRoot, sawDerived := false, false
	for _, addr := range dialed {
		if hasPrefixAddr(addr, "root-addr.onion") {
			sawRoot = true
		}
		if hasPrefixAddr(addr, "derived-addr.onion") {
			sawDerived = true
		}
	}
	if !sawRoot {
		t.Errorf("the fan-out didn't try the root address, addresses tried: %v", dialed)
	}
	if !sawDerived {
		t.Errorf("the fan-out didn't try the derived address (additional device), addresses tried: %v", dialed)
	}
}

func hasPrefixAddr(addr, prefix string) bool {
	return len(addr) >= len(prefix) && addr[:len(prefix)] == prefix
}

// errFakeDialRefused is a static error used only to make the fake dial
// above fail right away, without depending on a real network error.
var errFakeDialRefused = errors.New("connection refused (fake)")
