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
	"sync"

	"neutrino/internal/i18n"
)

// UnlockSlot tries one password combination against every slot in c
// and, on the first match, decrypts that slot's own content into a
// Keystore. idx and ki are returned alongside it so a later save can
// reseal exactly this slot (see slot_container.go's doc comment on
// slotContainer) without ever touching — or needing the password of —
// any other slot: not duress's, not any other real identity's, not any
// noise placeholder. ok reports whether any slot matched at all.
func UnlockSlot(c *slotContainer, passwordFile, passwordIdentity string) (idx int, ki []byte, ks *Keystore, ok bool, err error) {
	for i, s := range c.Slots {
		candidateKi, matched := unwrapKi(s, passwordFile, passwordIdentity)
		if !matched {
			continue
		}
		plain, err := openSlotContent(s, candidateKi)
		if err != nil {
			return 0, nil, nil, false, err
		}
		var out Keystore
		if err := json.Unmarshal(plain, &out); err != nil {
			return 0, nil, nil, false, errors.New(i18n.T("keystore.err_parse_json", err))
		}
		out.mu = &sync.Mutex{}
		return i, candidateKi, &out, true, nil
	}
	return 0, nil, nil, false, nil
}
