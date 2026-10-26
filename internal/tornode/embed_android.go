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

//go:build android

package tornode

// torBinary stays empty on Android: unlike the other platforms, the
// real Tor binary (libtor.so, from guardianproject/tor-android) isn't
// embedded via go:embed into the Go binary, it instead arrives as part
// of the APK packaging (jniLibs/<abi>/libtor.so) and is resolved at
// runtime via internal/androidnative.Resolve(), see StartTor in
// tornode.go.
//
// Build tag note: GOOS=android also satisfies the "linux" constraint
// (see "go help buildconstraint"), so embed_linux_amd64.go/
// embed_linux_arm64.go explicitly exclude "&& !android" to avoid
// conflicting with this file (otherwise "torBinary redeclared").
var torBinary []byte
