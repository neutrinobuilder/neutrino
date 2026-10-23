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

package version

import (
	"regexp"
	"testing"
)

func TestAppVersionFormat(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(AppVersion) {
		t.Fatalf("AppVersion %q doesn't match the N.N.N format", AppVersion)
	}
}

func TestBuildFormat(t *testing.T) {
	if !regexp.MustCompile(`^\d{10}$`).MatchString(Build) {
		t.Fatalf("Build %q doesn't match the YYMMDDNNNN format (10 digits)", Build)
	}
}

func TestFull(t *testing.T) {
	want := AppVersion + " (build " + Build + ")"
	if got := Full(); got != want {
		t.Fatalf("Full() = %q, want %q", got, want)
	}
}
