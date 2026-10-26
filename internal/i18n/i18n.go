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

// Package i18n provides translation of user-facing messages and TUI command
// names. The active language is set once at startup (no runtime switch
// within the same session: changing language requires a process restart).
package i18n

import "fmt"

type Lang string

const (
	LangIT Lang = "it"
	LangEN Lang = "en"
	LangFR Lang = "fr"
	LangDE Lang = "de"
	LangES Lang = "es"
	LangRO Lang = "ro"
	LangRU Lang = "ru"
)

// ParseLang normalizes a value read from config/user input. Any
// unrecognized value falls back to LangEN.
func ParseLang(s string) Lang {
	switch Lang(s) {
	case LangIT, LangFR, LangDE, LangES, LangRO, LangRU:
		return Lang(s)
	default:
		return LangEN
	}
}

var active Lang = LangEN

// SetActive sets the active language for the whole process. Must be called
// once at startup (during the wizard or right after reading the config),
// before any call to T/CommandName/ResolveCommand.
func SetActive(l Lang) {
	active = l
}

// T returns the message associated with key in the active language. If
// the key is missing from the active catalog, it falls back to the
// English catalog (always complete); if it's missing there too, it
// returns the key itself, making missing translations visible instead of
// hiding them.
func T(key string, args ...any) string {
	msg, ok := catalogs[active][key]
	if !ok {
		msg, ok = catalogs[LangEN][key]
	}
	if !ok {
		msg = key
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}
