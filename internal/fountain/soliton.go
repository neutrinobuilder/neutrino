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

package fountain

import "math"

// Standard parameters of the robust soliton distribution (Luby, 2002) —
// the same reference values used in the literature (c=0.1, δ=0.05). Fixed:
// encoder and decoder must agree on the same distribution to independently
// derive the same degree from a SymbolID, not meant to be adjustable per
// transfer.
const (
	solitonC     = 0.1
	solitonDelta = 0.05
)

// degreeCDF precomputes the robust soliton distribution's cumulative
// distribution function for k source blocks — once per transfer (k
// doesn't change within the same transfer). cdf[i] for i in [1,k]; cdf[0]
// stays 0 and is never used (the minimum possible degree is 1).
func degreeCDF(k int) []float64 {
	rho := make([]float64, k+1)
	rho[1] = 1 / float64(k)
	for i := 2; i <= k; i++ {
		rho[i] = 1 / (float64(i) * float64(i-1))
	}

	s := solitonC * math.Sqrt(float64(k)) * math.Log(float64(k)/solitonDelta)
	sk := int(math.Round(float64(k) / s))
	tau := make([]float64, k+1)
	for i := 1; i <= k; i++ {
		switch {
		case sk >= 1 && i < sk:
			tau[i] = s / (float64(i) * float64(k))
		case sk >= 1 && i == sk:
			tau[i] = s * math.Log(s/solitonDelta) / float64(k)
		}
	}

	mu := make([]float64, k+1)
	var z float64
	for i := 1; i <= k; i++ {
		mu[i] = rho[i] + tau[i]
		z += mu[i]
	}

	cdf := make([]float64, k+1)
	var acc float64
	for i := 1; i <= k; i++ {
		acc += mu[i] / z
		cdf[i] = acc
	}
	cdf[k] = 1 // corrects accumulated rounding error at the tail
	return cdf
}

// sampleDegree inverts the CDF for a uniform value r in [0,1) — linear
// search: k is at most a few thousand blocks per transfer, and the CDF is
// recomputed only once per transfer, not per symbol, so a binary search
// isn't needed here.
func sampleDegree(cdf []float64, r float64) int {
	for i := 1; i < len(cdf); i++ {
		if r <= cdf[i] {
			return i
		}
	}
	return len(cdf) - 1
}

// symbolIndices derives, from SymbolID and k, the same degree and the same
// set of source blocks on both the encoder and decoder side — no
// additional field needs to be transmitted beyond the ID itself.
func symbolIndices(id uint32, k int, cdf []float64) []int {
	rng := newSplitmix64(id)
	degree := min(sampleDegree(cdf, rng.float64()), k)
	if degree == k {
		indices := make([]int, k)
		for i := range indices {
			indices[i] = i
		}
		return indices
	}
	chosen := make(map[int]bool, degree)
	indices := make([]int, 0, degree)
	for len(indices) < degree {
		idx := rng.intn(k)
		if chosen[idx] {
			continue
		}
		chosen[idx] = true
		indices = append(indices, idx)
	}
	return indices
}
