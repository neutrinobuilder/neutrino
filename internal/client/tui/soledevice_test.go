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
	"testing"

	"neutrino/internal/keystore"
)

// TestContactInfoSoleDeviceOrPlaceholderEmptyDevices verifies that
// ContactInfo.SoleDeviceOrPlaceholder mirrors keystore.Contact.
// SoleDeviceOrPlaceholder: a contact with no entry at all in Devices
// still returns a usable DeviceRelation.
func TestContactInfoSoleDeviceOrPlaceholderEmptyDevices(t *testing.T) {
	c := ContactInfo{Username: "bob"}
	dev, ok := c.SoleDeviceOrPlaceholder()
	if !ok || dev == nil {
		t.Fatal("want a usable DeviceRelation for a contact without Devices")
	}
	if len(dev.RelIdentityPriv) != 0 || len(dev.RelContentPriv) != 0 {
		t.Error("the placeholder must have empty keys, ready for generation")
	}
}

// TestContactInfoSoleDeviceOrPlaceholderAmbiguousStillFalse verifies that
// with 2+ known devices it stays ambiguous, same behavior as SoleDevice.
func TestContactInfoSoleDeviceOrPlaceholderAmbiguousStillFalse(t *testing.T) {
	c := ContactInfo{Devices: map[string]*keystore.DeviceRelation{
		"d1": {}, "d2": {},
	}}
	if _, ok := c.SoleDeviceOrPlaceholder(); ok {
		t.Error("with 2+ known devices it must never pick one automatically")
	}
}
