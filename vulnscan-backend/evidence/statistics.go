package evidence

import (
	"math"
	"sort"
)

func moments(values []float64) (mean, cv float64) {
	var m2 float64
	for i, v := range values {
		d := v - mean
		mean += d / float64(i+1)
		m2 += d * (v - mean)
	}
	if len(values) > 0 && mean > 0 {
		cv = math.Sqrt(math.Max(0, m2/float64(len(values)))) / mean
	}
	return
}
func median(values []float64) float64 {
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	n := len(v)
	if n == 0 {
		return 0
	}
	if n%2 == 0 {
		return (v[n/2-1] + v[n/2]) / 2
	}
	return v[n/2]
}
func quantile(values []float64, p float64) float64 {
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	if len(v) == 0 {
		return 0
	}
	pos := p * float64(len(v)-1)
	a := int(pos)
	b := a + 1
	if b >= len(v) {
		return v[a]
	}
	return v[a] + (v[b]-v[a])*(pos-float64(a))
}

// Exact two-sided Kendall test without ties, via the permutation inversion distribution.
// A bounded sample size is required; no silent asymptotic fallback is used.
func exactKendall(values []float64) (int, float64, bool) {
	n := len(values)
	if n < 5 || n > 128 {
		return 0, 0, false
	}
	inversions := 0
	for i, a := range values {
		if !finite(a) {
			return 0, 0, false
		}
		for _, b := range values[i+1:] {
			if a == b {
				return 0, 0, false
			}
			if a > b {
				inversions++
			}
		}
	}
	dist := []float64{1}
	for m := 2; m <= n; m++ {
		next := make([]float64, m*(m-1)/2+1)
		for i, p := range dist {
			for j := 0; j < m; j++ {
				next[i+j] += p / float64(m)
			}
		}
		dist = next
	}
	total := n * (n - 1) / 2
	s := total - 2*inversions
	p := 0.0
	for i, v := range dist {
		if math.Abs(float64(total-2*i)) >= math.Abs(float64(s)) {
			p += v
		}
	}
	return s, math.Min(1, p), true
}

// Upper regularized incomplete gamma, used for the chi-square Ljung-Box tail.
func gammaQ(a, x float64) float64 {
	if x <= 0 {
		return 1
	}
	lg, _ := math.Lgamma(a)
	if x < a+1 {
		sum, term := 1/a, 1/a
		ap := a
		for i := 0; i < 10000; i++ {
			ap++
			term *= x / ap
			sum += term
			if math.Abs(term) < math.Abs(sum)*1e-14 {
				break
			}
		}
		return math.Max(0, math.Min(1, 1-sum*math.Exp(-x+a*math.Log(x)-lg)))
	}
	b := x + 1 - a
	c := 1e300
	d := 1 / b
	h := d
	for i := 1; i < 10000; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < 1e-300 {
			d = 1e-300
		}
		c = b + an/c
		if math.Abs(c) < 1e-300 {
			c = 1e-300
		}
		d = 1 / d
		delta := d * c
		h *= delta
		if math.Abs(delta-1) < 1e-14 {
			break
		}
	}
	return math.Max(0, math.Min(1, math.Exp(-x+a*math.Log(x)-lg)*h))
}
func ljungBox(values []float64, lags int) (float64, float64, float64, bool) {
	n := len(values)
	if lags < 1 || lags >= n {
		return 0, 0, 0, false
	}
	avg := 0.0
	for _, v := range values {
		avg += v
	}
	avg /= float64(n)
	den := 0.0
	for _, v := range values {
		den += (v - avg) * (v - avg)
	}
	if den == 0 {
		return 0, 1, 0, true
	}
	q, peak := 0.0, 0.0
	for k := 1; k <= lags; k++ {
		num := 0.0
		for i := k; i < n; i++ {
			num += (values[i] - avg) * (values[i-k] - avg)
		}
		rho := num / den
		if rho > peak {
			peak = rho
		}
		q += rho * rho / float64(n-k)
	}
	q *= float64(n * (n + 2))
	return q, gammaQ(float64(lags)/2, q/2), peak, true
}
func correlation(a, b []float64) (float64, bool) {
	if len(a) != len(b) || len(a) < 2 {
		return 0, false
	}
	ma, mb := 0.0, 0.0
	for i := range a {
		ma += a[i]
		mb += b[i]
	}
	ma /= float64(len(a))
	mb /= float64(len(b))
	num, da, db := 0.0, 0.0, 0.0
	for i := range a {
		x, y := a[i]-ma, b[i]-mb
		num += x * y
		da += x * x
		db += y * y
	}
	if da == 0 || db == 0 {
		return 0, false
	}
	return num / math.Sqrt(da*db), true
}
