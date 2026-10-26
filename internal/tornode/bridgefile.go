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

package tornode

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"neutrino/internal/i18n"
)

// LoadBridgeFile reads a bridge lines file (tor_bridges format: one
// line per bridge, blank lines and "#" comments ignored), read by
// cmd/main.go from --bridges-file or from the file saved by "neutrino
// get-bridges".
func LoadBridgeFile(path string) (*BridgeConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New(i18n.T("cli.err_no_bridges_in_file", path))
	}
	return &BridgeConfig{Lines: lines}, nil
}

// FilterBridgesByTransport keeps only the lines whose first field equals
// transport (e.g. "obfs4" or "webtunnel", the same value saved in
// bridge_default/bridge_fallback).
func FilterBridgesByTransport(bc *BridgeConfig, transport string) *BridgeConfig {
	var kept []string
	for _, line := range bc.Lines {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == transport {
			kept = append(kept, line)
		}
	}
	return &BridgeConfig{Lines: kept}
}
