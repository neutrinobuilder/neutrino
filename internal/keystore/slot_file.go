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

package keystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"neutrino/internal/i18n"
)

// slotFileOnDisk is the N-slot keystore file's outer container — a list
// of independent slotEntry blobs, no plaintext metadata about which are
// real/duress/noise.
type slotFileOnDisk struct {
	Slots []slotEntry `json:"slots"`
}

// WriteSlotContainer serializes c to path atomically — temp file in the
// same directory, fsync, then rename — the same pattern as
// Keystore.Save, so a kill mid-write never leaves a corrupted file:
// path keeps either its previous content or the fully new one.
func WriteSlotContainer(path string, c *slotContainer) error {
	data, err := json.Marshal(slotFileOnDisk{Slots: c.Slots})
	if err != nil {
		return errors.New(i18n.T("keystore.err_marshal", err))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New(i18n.T("keystore.err_create_dir", err))
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".keystore-*.tmp")
	if err != nil {
		return errors.New(i18n.T("keystore.err_tmp_file", err))
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath) // no-op if the rename below succeeded
	}()

	if err := tmp.Chmod(0600); err != nil {
		return errors.New(i18n.T("keystore.err_chmod", err))
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return errors.New(i18n.T("keystore.err_fsync", err))
	}
	tmp.Close()

	return os.Rename(tmpPath, path)
}

// ReadSlotContainer reads and parses path as an N-slot keystore file —
// no decryption happens here, just the outer container shape: every
// slot's own content stays sealed until someone tries a password
// combination against it (see slots.go, unwrapKi/openSlotContent).
func ReadSlotContainer(path string) (*slotContainer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_read_file", err))
	}
	var onDisk slotFileOnDisk
	if err := json.Unmarshal(data, &onDisk); err != nil {
		return nil, errors.New(i18n.T("keystore.err_format_unrecognized"))
	}
	return &slotContainer{Slots: onDisk.Slots}, nil
}
