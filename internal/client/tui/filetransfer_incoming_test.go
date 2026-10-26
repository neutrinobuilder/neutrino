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
	"os"
	"testing"
	"time"
)

// TestCloseTabAtDropsActiveIncomingTransfer verifies that closeTabAt calls
// dropIncomingTransfer for any transfer still active on the tab being
// closed, so startIncomingChunkWriter does not stay blocked forever on
// chunkCh (goroutine leak) and the already-written temporary file gets
// cleaned up (file leak). Verifies both the removal from the map and,
// indirectly, through the file disappearing from disk, that the writer
// goroutine actually received the abandon signal and exited.
func TestCloseTabAtDropsActiveIncomingTransfer(t *testing.T) {
	m := &model{
		tabs:              []*roomTab{{name: "room1"}},
		active:            0,
		consoleIdx:        0,
		incomingTransfers: make(map[string]*incomingFileTransfer),
	}

	chunkCh := make(chan incomingChunkJob, 4)
	chunkResultCh := make(chan incomingChunkResult, 4)
	abortCh := make(chan struct{})
	const transferID = "t1"
	m.incomingTransfers[transferID] = &incomingFileTransfer{
		transferID:    transferID,
		tabIdx:        0,
		chunkCh:       chunkCh,
		chunkResultCh: chunkResultCh,
		abortCh:       abortCh,
	}
	startIncomingChunkWriter(transferID, 10, chunkCh, abortCh, chunkResultCh)

	// A real chunk, to make the writer goroutine create a real temporary
	// file on disk, without this, closeTabAt would close a transfer that has
	// nothing to clean up yet, not exercising the removal of the
	// already-written file.
	chunkCh <- incomingChunkJob{seq: 0, chunk: []byte("hello")}
	var tmpPath string
	select {
	case res := <-chunkResultCh:
		if res.err != nil {
			t.Fatalf("chunk result: unexpected error %v", res.err)
		}
		tmpPath = res.tmpPath
	case <-time.After(2 * time.Second):
		t.Fatal("no result from the writer goroutine within the timeout")
	}
	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("the temporary file should exist before the tab is closed: %v", err)
	}

	m.closeTabAt(0)

	if _, ok := m.incomingTransfers[transferID]; ok {
		t.Fatal("closeTabAt: the transfer is still in m.incomingTransfers")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(tmpPath); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the temporary file %s wasn't removed after the tab was closed (writer goroutine never unblocked)", tmpPath)
}
