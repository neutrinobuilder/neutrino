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

//go:build neutrino_agent

package e2e

import (
	"strings"
	"testing"

	"neutrino/internal/client"
)

// commandCoverage maps every TUI slash command to the scenario that
// exercises it. TestCommandCoverage fails for any command of
// client.CommandList() (the same list the command palette is built from)
// missing here, so a new command can't stay untested by oversight.
var commandCoverage = map[string]string{
	"/cnt-add":                 "TestBasePairRoomMessages",
	"/grp-invite":              "TestBasePairRoomMessages",
	"/quit":                    "TestBaseQuitAndRestart",
	"/grp-file-send":           "TestFileSendTwoMembers",
	"/grp-contact-send":        "TestContactCardIntroduction",
	"/cnt-save":                "TestContactCardIntroduction",
	"/cnt-info":                "TestContactInfo",
	"/cnt-edit":                "TestContactEditLocalName",
	"/cnt-del":                 "TestContactDelete",
	"/cnt-ignore":              "TestContactCardIgnore",
	"/active":                  "TestActiveProbe",
	"/show-qr":                 "TestShowQRAndReadQRCode",
	"/cnt-read-qrcode":         "TestShowQRAndReadQRCode",
	"/grp-info":                "TestRoomInfoAndHealth",
	"/grp-health":              "TestRoomInfoAndHealth",
	"/grp-ping":                "TestRoomPing",
	"/msg":                     "TestRoomReplyReference",
	"/grp-msg-acks":            "TestRoomMsgAcks",
	"/grp-exit":                "TestRoomExit",
	"/grp-reconnect":           "TestRoomReconnect",
	"/grp-save":                "TestSavedGroupSaveRecallDelete",
	"/grp-recall":              "TestSavedGroupSaveRecallDelete",
	"/grp-del":                 "TestSavedGroupSaveRecallDelete",
	"/grp-join":                "TestGroupJoinWithoutInvite",
	"/grp-reinvite":            "TestGroupReinvite",
	"/grp-add-member":          "TestGroupAddMember",
	"/grp-ban":                 "TestGroupBan",
	"/grp-promote":             "TestGroupPromote",
	"/sec-safety":              "TestSafetyNumberAndVerify",
	"/sec-verify":              "TestSafetyNumberAndVerify",
	"/sec-unverify":            "TestSafetyNumberAndVerify",
	"/sec-pqc-sign":            "TestPQCSign",
	"/sec-rotate-rel-identity": "TestRotateRelKeys",
	"/sec-rotate-rel-content":  "TestRotateRelKeys",
	"/sec-rotate-key":          "TestRotateRootKey",
	"/sec-lock":                "TestInterfaceLock",
	"/sec-lock-pin":            "TestInterfaceLock",
	"/sec-lock-timeout":        "TestInterfaceLockTimeout",
	"/sec-passwd":              "TestPasswordChangeAndBackup",
	"/sec-backup":              "TestPasswordChangeAndBackup",
	"/help":                    "TestHelpAndInfoApp",
	"/info-app":                "TestHelpAndInfoApp",
	"/compact":                 "TestCompactAndConsoleExport",
	"/console-export":          "TestCompactAndConsoleExport",
	"/debug":                   "TestDebugToggle",
	"/sec-duress":              "TestDuressPassword",
	"/nukex":                   "TestNukeExpress",
	"/sec-nuke-timeout":        "TestNukeTimeout",
	"/sec-clear-all":           "TestClearAll",
	"/sec-device-label":        "TestDeviceLabel",
	"/sec-indoor-sync":         "TestIndoorSyncAndDevices",
	"/sec-devices":             "TestIndoorSyncAndDevices",
	"/sec-device-sync":         "TestDeviceSync",
	"/sec-remote-nuke":         "TestRemoteNuke",
}

func TestCommandCoverage(t *testing.T) {
	var missing []string
	known := map[string]bool{}
	for _, c := range client.CommandList() {
		known[c.Cmd] = true
		if _, ok := commandCoverage[c.Cmd]; !ok {
			missing = append(missing, c.Cmd)
		}
	}
	for cmd := range commandCoverage {
		if !known[cmd] {
			t.Errorf("commandCoverage lists %s, which is no longer a TUI command", cmd)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d of %d commands without a scenario: %s", len(missing), len(known), strings.Join(missing, " "))
	}
}
