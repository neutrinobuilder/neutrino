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

// Command decoygen compresses decoy_names.json into decoy_names.json.xz —
// the artifact actually go:embed'd into the binary (see decoy_names.go).
// The plain JSON stays the auditable source of truth in the repository;
// re-run this (go generate ./internal/keystore) whenever decoy_names.json
// changes, and commit the regenerated .xz alongside it.
package main

import (
	"os"

	"github.com/ulikunitz/xz"
)

func main() {
	plain, err := os.ReadFile("decoy_names.json")
	if err != nil {
		panic(err)
	}
	out, err := os.Create("decoy_names.json.xz")
	if err != nil {
		panic(err)
	}
	defer out.Close()
	w, err := xz.NewWriter(out)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(plain); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
}
