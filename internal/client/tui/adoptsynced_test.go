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
	"testing"

	"neutrino/internal/keystore"
)

// TestAdoptSyncedContacts verifies what a sync between our own devices
// brings into memory: a contact not shown yet is added, an existing one
// gets the devices it lacks, a device already in memory keeps its
// in-memory state, and a placeholder the keystore replaced is dropped.
func TestAdoptSyncedContacts(t *testing.T) {
	bobPub := bytes.Repeat([]byte{1}, 32)
	carolPub := bytes.Repeat([]byte{2}, 32)
	memDev := &keystore.DeviceRelation{Address: "in-memory"}
	m := &model{
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices:     map[string]*keystore.DeviceRelation{"phone": memDev, "": {}},
		}},
		contactsSnapshot: func() []ContactInfo {
			return []ContactInfo{
				{Username: "bob", IdentityPub: bobPub, Devices: map[string]*keystore.DeviceRelation{
					"phone":  {Address: "from-keystore"},
					"laptop": {Address: "laptop-addr"},
				}},
				{Username: "carol", IdentityPub: carolPub},
			}
		},
	}

	m.adoptSyncedContacts()

	if len(m.contacts) != 2 || m.contacts[1].Username != "carol" {
		t.Fatalf("contacts = %+v, want bob and carol", m.contacts)
	}
	bob := m.contacts[0]
	if bob.Devices["phone"] != memDev || memDev.Address != "in-memory" {
		t.Error("a device already in memory was overwritten")
	}
	if dev := bob.Devices["laptop"]; dev == nil || dev.Address != "laptop-addr" {
		t.Errorf("missing device not adopted: %+v", bob.Devices)
	}
	if _, ok := bob.Devices[""]; ok {
		t.Error("placeholder kept although the keystore replaced it")
	}

	// A second run with nothing new changes nothing.
	m.adoptSyncedContacts()
	if len(m.contacts) != 2 || len(m.contacts[0].Devices) != 2 {
		t.Errorf("second adoption changed the address book: %+v", m.contacts)
	}
}
