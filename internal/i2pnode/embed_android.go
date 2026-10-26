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

package i2pnode

// i2pdBinary stays empty on Android: unlike the other platforms, the
// real i2pd binary (from PurpleI2P/i2pd-android, a standalone ELF
// already executable, not disguised) isn't embedded via go:embed into
// the Go binary, instead it arrives as part of APK packaging
// (jniLibs/<abi>/libi2pd.so) and is resolved at runtime through
// internal/androidnative.Resolve(), see resolveBinary in i2pnode.go.
//
// Build tag note: GOOS=android also satisfies "linux" constraints (see
// "go help buildconstraint"), so embed_linux_amd64.go/embed_linux_arm64.go
// explicitly exclude "&& !android" to avoid conflicting with this file
// (otherwise "i2pdBinary redeclared"), the same scheme already applied
// in internal/tornode for Tor.
var i2pdBinary []byte
