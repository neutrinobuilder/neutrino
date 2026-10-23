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

package indoor

import (
	"bytes"
	"crypto/rand"
	"testing"

	"neutrino/internal/keystore"
)

func TestAnnouncePacketRoundtrip(t *testing.T) {
	hash := make([]byte, 16)
	rand.Read(hash)
	instanceID := make([]byte, 8)
	rand.Read(instanceID)

	raw, err := EncodeAnnounce(AnnouncePacket{Version: ProtocolVersion, IdentityHash: hash, InstanceID: instanceID})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodeAnnounce(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Version != ProtocolVersion {
		t.Errorf("Version = %d, want %d", pkt.Version, ProtocolVersion)
	}
	if !bytes.Equal(pkt.IdentityHash, hash) {
		t.Error("IdentityHash doesn't survive the round-trip")
	}
	if !bytes.Equal(pkt.InstanceID, instanceID) {
		t.Error("InstanceID doesn't survive the round-trip")
	}
}

func TestSyncPayloadRoundtrip(t *testing.T) {
	pub := make([]byte, 32)
	rand.Read(pub)
	devID := make([]byte, 16)
	rand.Read(devID)

	p := SyncPayload{
		Contacts: []keystore.Contact{{Username: "bob", IdentityPub: pub}},
		Device:   keystore.DeviceRecord{DeviceID: devID, Label: "test"},
	}
	raw, err := MarshalSyncPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSyncPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Contacts) != 1 || got.Contacts[0].Username != "bob" {
		t.Errorf("Contacts doesn't survive the round-trip: %+v", got.Contacts)
	}
	if !bytes.Equal(got.Device.DeviceID, devID) {
		t.Error("Device.DeviceID doesn't survive the round-trip")
	}
}

func TestUnmarshalSyncPayloadRejectsMissingDeviceID(t *testing.T) {
	raw, _ := MarshalSyncPayload(SyncPayload{})
	if _, err := UnmarshalSyncPayload(raw); err == nil {
		t.Fatal("a payload without DeviceID must be refused, not silently accepted")
	}
}
