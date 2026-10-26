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
	"os"
	"os/exec"

	"neutrino/internal/keystore"
)

// spawnPod starts the pod as a SEPARATE OS process (self-exec of this
// same binary via the hidden "__pod" subcommand, never a goroutine — a
// goroutine would die together with this process if something kills it
// with force, exactly the scenario the pod must survive) and feeds it
// snapshot as JSON over stdin ONLY — never argv/env: the snapshot
// carries contact addresses and other metadata that must not land in
// `ps`/`/proc/<pid>/cmdline`/`environ`, readable by any other process
// on the same machine.
//
// Never waits for the pod to finish — the caller must never block on
// this call: no delay may be perceptible to the user or to whoever is
// watching the device. A background goroutine reaps the child
// once it exits so it never lingers as a zombie; this does NOT make
// spawnPod itself wait, since Start() already returned before that
// goroutine runs.
//
// args/env exist for testability (the production call site always
// passes args=["__pod"], env=nil — see runPod/main.go's switch): a test
// can point exePath at the test binary itself and use args/env to
// select a helper-process test function instead (the standard
// os/exec "TestHelperProcess" pattern), without spawnPod needing to
// know anything about that.
func spawnPod(exePath string, args []string, env []string, snapshot keystore.PodSnapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	cmd := exec.Command(exePath, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_, _ = stdin.Write(data)
		_ = stdin.Close()
	}()
	go func() {
		_ = cmd.Wait() // reap only — never blocks the caller, runs in its own goroutine
	}()
	return nil
}
