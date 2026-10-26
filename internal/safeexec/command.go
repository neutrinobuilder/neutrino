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

package safeexec

import (
	"os/exec"
	"path/filepath"
)

// Command is a drop-in replacement for exec.Command that resolves name via
// the safe LookPath above instead of exec.Command's own internal call to the
// real (crash-prone) os/exec.LookPath: exec.Command performs that lookup
// itself, internally, whenever name has no path separator — even if the
// caller never calls exec.LookPath directly. Mirrors exec.Command's own
// construction logic (see os/exec/exec.go, func Command) for the Linux case;
// callers on this project never run on Windows, so the PATHEXT branch there
// is not replicated.
func Command(name string, arg ...string) *exec.Cmd {
	cmd := &exec.Cmd{
		Path: name,
		Args: append([]string{name}, arg...),
	}
	if filepath.Base(name) == name {
		if lp, err := LookPath(name); err != nil {
			cmd.Err = err
		} else {
			cmd.Path = lp
		}
	}
	return cmd
}
