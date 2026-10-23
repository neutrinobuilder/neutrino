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

package i18n

import (
	_ "embed"
	"encoding/json"
	"maps"
)

// catalogs collects, per language, all key→message maps. Populated in
// init() from Neutrino-i18n-data.json (embedded via go:embed), the single
// source of truth for translation data.
var catalogs = map[Lang]map[string]string{
	LangIT: {},
	LangEN: {},
	LangFR: {},
	LangDE: {},
	LangES: {},
	LangRO: {},
	LangRU: {},
}

func register(l Lang, entries map[string]string) {
	maps.Copy(catalogs[l], entries)
}

//go:embed Neutrino-i18n-data.json
var catalogJSON []byte

type catalogEntry struct {
	Key string `json:"key"`
	En  string `json:"en"`
	It  string `json:"it"`
	Fr  string `json:"fr"`
	De  string `json:"de"`
	Es  string `json:"es"`
	Ro  string `json:"ro"`
	Ru  string `json:"ru"`
}

func init() {
	var entries []catalogEntry
	if err := json.Unmarshal(catalogJSON, &entries); err != nil {
		panic("i18n: Neutrino-i18n-data.json is malformed: " + err.Error())
	}
	byLang := map[Lang]map[string]string{
		LangIT: {}, LangEN: {}, LangFR: {}, LangDE: {},
		LangES: {}, LangRO: {}, LangRU: {},
	}
	for _, e := range entries {
		byLang[LangIT][e.Key] = e.It
		byLang[LangEN][e.Key] = e.En
		byLang[LangFR][e.Key] = e.Fr
		byLang[LangDE][e.Key] = e.De
		byLang[LangES][e.Key] = e.Es
		byLang[LangRO][e.Key] = e.Ro
		byLang[LangRU][e.Key] = e.Ru
	}
	for l, m := range byLang {
		register(l, m)
	}
}
