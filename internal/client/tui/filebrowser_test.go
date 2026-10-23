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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- sendFileGoUp / sendFileEnter ---------------------------------------------

func TestSendFileGoUpNavigatesToParent(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	sibling := filepath.Join(root, "sibling.txt")
	if err := os.WriteFile(sibling, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := model{sendFileDir: sub, sendFileFilter: "leftover"}
	m2 := m.sendFileGoUp()

	if m2.sendFileDir != root {
		t.Fatalf("sendFileDir after GoUp = %q, want %q", m2.sendFileDir, root)
	}
	if m2.sendFileFilter != "" {
		t.Fatalf("sendFileFilter after GoUp = %q, want it cleared", m2.sendFileFilter)
	}
	found := false
	for _, e := range m2.sendFileEntries {
		if e.name == "sibling.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sendFileEntries after GoUp = %v, want it to contain sibling.txt", m2.sendFileEntries)
	}
}

func TestSendFileGoUpAtFilesystemRootIsNoop(t *testing.T) {
	root := "/"
	if runtime.GOOS == "windows" {
		t.Skip("filesystem root not applicable on Windows")
	}
	m := model{sendFileDir: root}
	m2 := m.sendFileGoUp()
	if m2.sendFileDir != root {
		t.Fatalf("sendFileGoUp from the root = %q, want unchanged %q", m2.sendFileDir, root)
	}
}

func TestSendFileGoUpWithUnreadableParentKeepsModelUnchanged(t *testing.T) {
	// filepath.Dir of an already-removed directory can return a path that
	// is no longer readable — sendFileGoUp must silently stay where it was,
	// never propagate the error nor alter the state.
	root := t.TempDir()
	ghost := filepath.Join(root, "no-longer-exists", "even-deeper")
	m := model{sendFileDir: ghost}
	m2 := m.sendFileGoUp()
	if m2.sendFileDir != ghost {
		t.Fatalf("sendFileGoUp with an unreadable parent changed sendFileDir: %q, want unchanged %q", m2.sendFileDir, ghost)
	}
}

func TestSendFileEnterDescendsIntoSubdirectory(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "docs")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := model{sendFileDir: root, sendFileIdx: 3, sendFileFilter: "leftover"}
	m2 := m.sendFileEnter(sub)

	if m2.sendFileDir != sub {
		t.Fatalf("sendFileDir after Enter = %q, want %q", m2.sendFileDir, sub)
	}
	if m2.sendFileIdx != 0 {
		t.Fatalf("sendFileIdx after Enter = %d, want 0 (reset)", m2.sendFileIdx)
	}
	if m2.sendFileFilter != "" {
		t.Fatalf("sendFileFilter after Enter = %q, want it cleared", m2.sendFileFilter)
	}
	if len(m2.sendFileEntries) != 1 || m2.sendFileEntries[0].name != "a.txt" {
		t.Fatalf("sendFileEntries after Enter = %v, want [a.txt]", m2.sendFileEntries)
	}
}

func TestSendFileEnterOnUnreadableTargetKeepsModelUnchanged(t *testing.T) {
	root := t.TempDir()
	notADir := filepath.Join(root, "file.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := model{sendFileDir: root, sendFileIdx: 5}
	// notADir is not a directory: listDir fails, sendFileEnter must
	// silently stay where it was (no error popup for a common navigation
	// event).
	m2 := m.sendFileEnter(notADir)
	if m2.sendFileDir != root || m2.sendFileIdx != 5 {
		t.Fatalf("sendFileEnter on an unreadable target altered the model: dir=%q idx=%d, want them unchanged", m2.sendFileDir, m2.sendFileIdx)
	}
}

// --- saveDirGoUp / saveDirEnter -------------------------------------------------

func TestSaveDirGoUpFiltersToSubdirectoriesOnly(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sibling-dir"), 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sibling-file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := model{saveFileDir: sub}
	m2 := m.saveDirGoUp()
	if m2.saveFileDir != root {
		t.Fatalf("saveFileDir after saveDirGoUp = %q, want %q", m2.saveFileDir, root)
	}
	for _, e := range m2.saveFileEntries {
		if !e.isDir {
			t.Fatalf("saveFileEntries after saveDirGoUp contains a file: %+v — want only folders", e)
		}
	}
	// root contains two subfolders: "sub" (the one just ascended from, itself
	// a child of root) and "sibling-dir" — never the file sibling-file.txt.
	// Case-insensitive alphabetical order: sibling-dir, sub.
	if len(m2.saveFileEntries) != 2 || m2.saveFileEntries[0].name != "sibling-dir" || m2.saveFileEntries[1].name != "sub" {
		t.Fatalf("saveFileEntries after saveDirGoUp = %v, want [sibling-dir, sub]", m2.saveFileEntries)
	}
}

func TestSaveDirEnterDescendsAndFiltersToSubdirectoriesOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "child", "grandchild"), 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "child", "leaf.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := model{saveFileDir: root, saveFileIdx: 4}
	m2 := m.saveDirEnter("child")

	wantDir := filepath.Join(root, "child")
	if m2.saveFileDir != wantDir {
		t.Fatalf("saveFileDir after saveDirEnter = %q, want %q", m2.saveFileDir, wantDir)
	}
	if m2.saveFileIdx != 0 {
		t.Fatalf("saveFileIdx after saveDirEnter = %d, want 0 (reset)", m2.saveFileIdx)
	}
	if len(m2.saveFileEntries) != 1 || m2.saveFileEntries[0].name != "grandchild" {
		t.Fatalf("saveFileEntries after saveDirEnter = %v, want only [grandchild] (never leaf.txt)", m2.saveFileEntries)
	}
}

// --- render popups (browser file/save) -----------------------------------------

func TestRenderSaveRenamePopupShowsProposedName(t *testing.T) {
	m := model{savePendingName: "important-document.pdf"}
	out := m.renderSaveRenamePopup()
	if !strings.Contains(out, "important-document.pdf") {
		t.Fatalf("renderSaveRenamePopup doesn't contain the proposed name: %q", out)
	}
}

func TestRenderSaveDirBrowserListsSaveHereAndSubdirs(t *testing.T) {
	m := model{
		savePendingName: "file.bin",
		saveFileDir:     "/tmp/dest",
		saveFileEntries: []fsEntry{{name: "alpha", isDir: true}, {name: "beta", isDir: true}},
		saveFileIdx:     0,
	}
	out := m.renderSaveDirBrowser()
	if !strings.Contains(out, "alpha/") || !strings.Contains(out, "beta/") {
		t.Fatalf("renderSaveDirBrowser doesn't list the expected subfolders: %q", out)
	}
}

// --- compactChatLines -----------------------------------------------------------

func TestCompactChatLinesCollapsesConsecutiveDuplicatesKeepingLast(t *testing.T) {
	in := []chatLine{
		{text: "a", timestamp: "10:00"},
		{text: "a", timestamp: "10:01"},
		{text: "a", timestamp: "10:02"},
		{text: "b", timestamp: "10:03"},
		{text: "a", timestamp: "10:04"},
	}
	out := compactChatLines(in)
	if len(out) != 3 {
		t.Fatalf("compactChatLines has %d lines, want 3 (a@10:02, b, a@10:04)", len(out))
	}
	if out[0].text != "a" || out[0].timestamp != "10:02" {
		t.Fatalf("out[0] = %+v, want the LAST occurrence of the \"a\" run (10:02)", out[0])
	}
	if out[1].text != "b" {
		t.Fatalf("out[1] = %+v, want \"b\"", out[1])
	}
	if out[2].text != "a" || out[2].timestamp != "10:04" {
		t.Fatalf("out[2] = %+v, want \"a\"@10:04", out[2])
	}
}

func TestCompactChatLinesNoDuplicatesReturnsSameLength(t *testing.T) {
	in := []chatLine{{text: "a"}, {text: "b"}, {text: "c"}}
	out := compactChatLines(in)
	if len(out) != 3 {
		t.Fatalf("compactChatLines without duplicates = %d lines, want 3", len(out))
	}
}

func TestCompactChatLinesNeverMutatesInput(t *testing.T) {
	in := []chatLine{{text: "a"}, {text: "a"}}
	inCopy := append([]chatLine(nil), in...)
	_ = compactChatLines(in)
	if in[0].text != inCopy[0].text || in[1].text != inCopy[1].text {
		t.Fatal("compactChatLines mutated the input slice")
	}
}

// --- resolveNameOrPickerKey / resolveContactArg --------------------------

func TestResolveNameOrPickerKeyEmptyStringNeverResolves(t *testing.T) {
	// Without this guard, "" would always resolve to the first contact
	// with an empty LocalName.
	m := &model{contacts: []ContactInfo{{Username: "alice", LocalName: ""}}}
	if got := m.resolveNameOrPickerKey(""); got != nil {
		t.Fatalf("resolveNameOrPickerKey(\"\") = %+v, want nil", got)
	}
}

func TestResolveNameOrPickerKeyPrefersLocalNameOverUsername(t *testing.T) {
	m := &model{contacts: []ContactInfo{
		{Username: "realname", LocalName: "Mario"},
		{Username: "Mario", LocalName: ""}, // username matches the other one's LocalName
	}}
	got := m.resolveNameOrPickerKey("Mario")
	if got == nil || got.Username != "realname" {
		t.Fatalf("resolveNameOrPickerKey(\"Mario\") = %+v, want the contact with LocalName=Mario (username=realname)", got)
	}
}

func TestResolveContactArgReportsAmbiguity(t *testing.T) {
	m := &model{contacts: []ContactInfo{
		{Username: "bob", IdentityPub: testPub("bob-1")},
		{Username: "bob", IdentityPub: testPub("bob-2"), LocalName: "Roberto"},
		{Username: "carol", IdentityPub: testPub("carol")},
	}}
	if c, n := m.resolveContactArg("bob"); c != nil || n != 2 {
		t.Errorf("resolveContactArg(bob) = %v, %d; want nil, 2 (ambiguous)", c, n)
	}
	if c, n := m.resolveContactArg("Roberto"); n != 1 || !bytes.Equal(c.IdentityPub, testPub("bob-2")) {
		t.Errorf("resolveContactArg(Roberto) = %v, %d; want the second bob", c, n)
	}
	if c, n := m.resolveContactArg(contactPickerKey(m.contacts[0])); n != 1 || !bytes.Equal(c.IdentityPub, testPub("bob-1")) {
		t.Errorf("resolveContactArg(picker key) = %v, %d; want the first bob", c, n)
	}
	if c, n := m.resolveContactArg("nobody"); c != nil || n != 0 {
		t.Errorf("resolveContactArg(nobody) = %v, %d; want nil, 0", c, n)
	}
}

func TestResolveMemberArgReportsAmbiguity(t *testing.T) {
	m := &model{myUsername: "me", myIdentityPub: testPub("me")}
	tab := &roomTab{groupMembers: []GroupMember{
		{Username: "me", IdentityPub: testPub("me")},
		{Username: "bob", IdentityPub: testPub("bob-1")},
		{Username: "bob", IdentityPub: testPub("bob-2")},
		{Username: "carol", IdentityPub: testPub("carol")},
	}}
	tab.setGroupLabels()
	if _, n := m.resolveMemberArg(tab, "bob", nil); n != 2 {
		t.Errorf("resolveMemberArg(bob): %d matches, want 2", n)
	}
	if gm, n := m.resolveMemberArg(tab, "CAROL", nil); n != 1 || !bytes.Equal(gm.IdentityPub, testPub("carol")) {
		t.Errorf("resolveMemberArg(CAROL) = %v, %d; want carol", gm, n)
	}
	if gm, n := m.resolveMemberArg(tab, memberPickerKey(tab.groupMembers[2]), nil); n != 1 || !bytes.Equal(gm.IdentityPub, testPub("bob-2")) {
		t.Errorf("resolveMemberArg(picker key) = %v, %d; want the second bob", gm, n)
	}
}

// --- msgAcksPreview ---------------------------------------------------------------

func TestMsgAcksPreviewShortTextUnchanged(t *testing.T) {
	short := "ciao"
	if got := msgAcksPreview(short); got != short {
		t.Fatalf("msgAcksPreview(%q) = %q, want unchanged", short, got)
	}
}

func TestMsgAcksPreviewTruncatesLongTextWithEllipsis(t *testing.T) {
	long := strings.Repeat("x", msgAcksPreviewLen+20)
	got := msgAcksPreview(long)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("msgAcksPreview on a long text = %q, want it to end with …", got)
	}
	if len([]rune(got)) != msgAcksPreviewLen+1 {
		t.Fatalf("len(msgAcksPreview) = %d, want %d (truncated + ellipsis)", len([]rune(got)), msgAcksPreviewLen+1)
	}
}

func TestMsgAcksPreviewExactLengthUnchanged(t *testing.T) {
	exact := strings.Repeat("y", msgAcksPreviewLen)
	if got := msgAcksPreview(exact); got != exact {
		t.Fatalf("msgAcksPreview on a text exactly at the limit = %q, want unchanged", got)
	}
}
