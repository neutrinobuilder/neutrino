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

//go:generate go run ./decoygen

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"math/rand"

	"github.com/ulikunitz/xz"
)

//go:embed decoy_names.json.xz
var decoyNamesXZ []byte

// decoyTier: one gender's names split into three frequency bands, weighted
// in decoyPickFrom.
type decoyTier struct {
	Common []string `json:"common"`
	Medium []string `json:"medium"`
	Rare   []string `json:"rare"`
}

type decoyLocale struct {
	Male   decoyTier `json:"male"`
	Female decoyTier `json:"female"`
}

// decoyNameData mirrors decoy_names.json: one decoyLocale per ISO language
// code (it/en/fr/de/es/ro/ru), plus intl[zh/ar/sa].
var decoyNameData struct {
	locales map[string]decoyLocale
	intl    map[string]decoyLocale
}

func init() {
	r, err := xz.NewReader(bytes.NewReader(decoyNamesXZ))
	if err != nil {
		panic(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(plain, &raw); err != nil {
		panic(err)
	}
	decoyNameData.locales = map[string]decoyLocale{}
	decoyNameData.intl = map[string]decoyLocale{}
	for key, msg := range raw {
		if key == "intl" {
			var intlRaw map[string]json.RawMessage
			if err := json.Unmarshal(msg, &intlRaw); err != nil {
				panic(err)
			}
			for sub, subMsg := range intlRaw {
				var loc decoyLocale
				if err := json.Unmarshal(subMsg, &loc); err != nil {
					panic(err)
				}
				decoyNameData.intl[sub] = loc
			}
			continue
		}
		var loc decoyLocale
		if err := json.Unmarshal(msg, &loc); err != nil {
			panic(err)
		}
		decoyNameData.locales[key] = loc
	}
}

// decoyWeight{Common,Medium,Rare}: relative odds for decoyPickFrom.
const (
	decoyWeightCommon = 70
	decoyWeightMedium = 25
	decoyWeightRare   = 5
)

func decoyPickFrom(t decoyTier) string {
	pools := make([]struct {
		list   []string
		weight int
	}, 0, 3)
	if len(t.Common) > 0 {
		pools = append(pools, struct {
			list   []string
			weight int
		}{t.Common, decoyWeightCommon})
	}
	if len(t.Medium) > 0 {
		pools = append(pools, struct {
			list   []string
			weight int
		}{t.Medium, decoyWeightMedium})
	}
	if len(t.Rare) > 0 {
		pools = append(pools, struct {
			list   []string
			weight int
		}{t.Rare, decoyWeightRare})
	}
	if len(pools) == 0 {
		return ""
	}
	total := 0
	for _, p := range pools {
		total += p.weight
	}
	roll := rand.Intn(total)
	for _, p := range pools {
		if roll < p.weight {
			return p.list[rand.Intn(len(p.list))]
		}
		roll -= p.weight
	}
	last := pools[len(pools)-1].list
	return last[rand.Intn(len(last))]
}

// splitSecondaryLangs parses config.Config.DecoySecondaryLangs's
// comma-separated ISO codes, trimming spaces, dropping empties and any
// code with no entry in decoyNameData.locales.
func splitSecondaryLangs(csv string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(csv); i++ {
		if i == len(csv) || csv[i] == ',' {
			code := trimSpace(csv[start:i])
			if code != "" {
				if _, ok := decoyNameData.locales[code]; ok {
					out = append(out, code)
				}
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// DecoyFirstName returns one first name. primaryLang is cfg.Lang;
// secondaryLangsCSV/secondaryPct/intlPct are
// cfg.DecoySecondaryLangs/DecoySecondaryLangPct/DecoyIntlPct. female=true
// picks from the female list, otherwise male. Falls back to primaryLang,
// then "it", if a pick comes up empty.
func DecoyFirstName(primaryLang, secondaryLangsCSV string, secondaryPct, intlPct int, female bool) string {
	if intlPct > 0 && rand.Intn(100) < intlPct && len(decoyNameData.intl) > 0 {
		keys := make([]string, 0, len(decoyNameData.intl))
		for k := range decoyNameData.intl {
			keys = append(keys, k)
		}
		loc := decoyNameData.intl[keys[rand.Intn(len(keys))]]
		if name := decoyPickGendered(loc, female); name != "" {
			return name
		}
	}

	lang := primaryLang
	secondary := splitSecondaryLangs(secondaryLangsCSV)
	if len(secondary) > 0 && secondaryPct > 0 && rand.Intn(100) < secondaryPct {
		lang = secondary[rand.Intn(len(secondary))]
	}
	loc, ok := decoyNameData.locales[lang]
	if !ok {
		loc, ok = decoyNameData.locales[primaryLang]
	}
	if !ok {
		loc = decoyNameData.locales["it"]
	}
	return decoyPickGendered(loc, female)
}

func decoyPickGendered(loc decoyLocale, female bool) string {
	if female {
		return decoyPickFrom(loc.Female)
	}
	return decoyPickFrom(loc.Male)
}

// decoyAlphabets: letters DecoyLocalInitial draws from, per lang. No entry
// for intl's zh/ar/sa.
var decoyAlphabets = map[string]string{
	"it": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"en": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"fr": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"de": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"es": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"ro": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"ru": "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЭЮЯ",
}

// DecoyLocalInitial returns one random uppercase letter + "." (e.g. "P."),
// or "" if lang has no entry in decoyAlphabets.
func DecoyLocalInitial(lang string) string {
	letters, ok := decoyAlphabets[lang]
	if !ok || letters == "" {
		return ""
	}
	runes := []rune(letters)
	return string(runes[rand.Intn(len(runes))]) + "."
}

// DecoyContactName returns (username, localName) for one fabricated
// contact. username is always just the generated first name. localName is
// first+" "+DecoyLocalInitial(lang) when existingFirstNames[username] is
// true (first name collides with another duress contact) or, with
// probability initialPct (0-100), even when it doesn't; otherwise "".
func DecoyContactName(primaryLang, secondaryLangsCSV string, secondaryPct, intlPct, initialPct int, female bool, existingFirstNames map[string]bool) (username, localName string) {
	username = DecoyFirstName(primaryLang, secondaryLangsCSV, secondaryPct, intlPct, female)
	collides := existingFirstNames[username]
	if collides || (initialPct > 0 && rand.Intn(100) < initialPct) {
		if initial := DecoyLocalInitial(primaryLang); initial != "" {
			localName = username + " " + initial
		}
	}
	return username, localName
}
