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

package main

import (
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"neutrino/internal/keystore"
)

// TestMain intercepts a special subprocess invocation
// (GO_WANT_POD_HELPER=1) so spawnPod can be tested end-to-end without
// needing the real `neutrino` binary or its "__pod" dispatch in
// main(): spawnPod only cares that SOME process reads stdin and exits,
// not which one, the standard os/exec "helper process" pattern (see
// the Go standard library's own exec_test.go). Every other invocation
// (the normal `go test` run) falls through to m.Run() unchanged.
func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_POD_HELPER") == "1" {
		podHelperProcess()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// podHelperProcess stands in for runPod() (cmd/pod.go) in this test:
// reads whatever spawnPod wrote to stdin and dumps it verbatim to the
// file named by POD_HELPER_OUT, so the test can inspect exactly what
// crossed the pipe.
func podHelperProcess() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(1)
	}
	out := os.Getenv("POD_HELPER_OUT")
	if out == "" {
		os.Exit(1)
	}
	if err := os.WriteFile(out, data, 0600); err != nil {
		os.Exit(1)
	}
}

func TestSpawnPodDeliversSnapshotOverStdin(t *testing.T) {
	outFile := t.TempDir() + "/pod_stdin.json"
	snap := keystore.PodSnapshot{
		NetKind: "tor",
		Targets: []keystore.PodRevokeTarget{
			{Address: "addr1.onion", ContactIdentityPub: []byte("contact-pub-000000000000000000"), DevicePub: []byte("device-pub-0")},
		},
	}

	err := spawnPod(os.Args[0], nil, []string{"GO_WANT_POD_HELPER=1", "POD_HELPER_OUT=" + outFile}, snap)
	if err != nil {
		t.Fatalf("spawnPod: %v", err)
	}

	// spawnPod never waits by design, poll briefly for the helper to
	// finish writing, same spirit as every other best-effort wait in
	// this codebase (e.g. remoteNukeExecuteTimeout), never a fixed sleep.
	var got []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(outFile)
		if err == nil && len(b) > 0 {
			got = b
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got == nil {
		t.Fatal("helper process never wrote the file, stdin pipe not delivered?")
	}

	var decoded keystore.PodSnapshot
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.NetKind != "tor" {
		t.Errorf("decoded header mismatch: %+v", decoded)
	}
	if len(decoded.Targets) != 1 || decoded.Targets[0].Address != "addr1.onion" {
		t.Errorf("decoded targets mismatch: %+v", decoded.Targets)
	}
}

func TestSpawnPodNeverBlocksCaller(t *testing.T) {
	// The helper process never receives POD_HELPER_OUT here, so it
	// exits(1) almost immediately without writing anything, spawnPod
	// itself must still return right away, regardless of what the child
	// does or how fast it dies.
	start := time.Now()
	err := spawnPod(os.Args[0], nil, []string{"GO_WANT_POD_HELPER=1"}, keystore.PodSnapshot{})
	if err != nil {
		t.Fatalf("spawnPod: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("spawnPod took %v to return, should never wait for the child", elapsed)
	}
}
