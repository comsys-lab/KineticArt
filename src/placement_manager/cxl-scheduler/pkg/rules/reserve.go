package rules

type CurvePt struct{ N, Ratio float64 }

var MLBECurve = []CurvePt{{0, 1.0000}, {4, 1.1062}, {8, 1.2437}, {12, 1.4053}, {16, 1.6263}, {20, 1.9126}, {24, 2.2787}}

func Slope(c []CurvePt, s float64) float64 {
	i := 0
	for i < len(c)-2 && s >= c[i+1].Ratio {
		i++
	}
	return (c[i+1].Ratio - c[i].Ratio) / (c[i+1].N - c[i].N)
}

type Reservation struct {
	Pod   string
	T0    float64
	Eff0  float64
	Delta float64
	Since float64
}

type CXLReserve struct {
	Curve     []CurvePt
	FillRatio float64
	FillHold  float64
	Grace     float64
	List      []Reservation
}

func (r *CXLReserve) sum() float64 {
	s := 0.0
	for _, x := range r.List {
		s += x.Delta
	}
	return s
}

func (r *CXLReserve) Effective(obs float64) float64 {
	if obs <= 0 {
		return obs
	}
	return obs + r.sum()
}

func (r *CXLReserve) Next(obs float64) float64 {
	if obs <= 0 {
		return 0
	}
	return Slope(r.Curve, r.Effective(obs))
}

func (r *CXLReserve) Add(pod string, now, obs float64) Reservation {
	x := Reservation{Pod: pod, T0: now, Eff0: r.Effective(obs), Delta: r.Next(obs)}
	if obs <= 0 {
		x.Eff0, x.Delta = 99, Slope(r.Curve, 1.0)
	}
	r.List = append(r.List, x)
	return x
}

func (r *CXLReserve) Release(now, obs float64) (out []Reservation, why []string) {
	keep := r.List[:0]
	for _, x := range r.List {
		if obs > 0 && obs-x.Eff0 >= r.FillRatio*x.Delta {
			if x.Since == 0 {
				x.Since = now
			}
		} else {
			x.Since = 0
		}
		switch {
		case x.Since > 0 && now-x.Since >= r.FillHold:
			out, why = append(out, x), append(why, "filled")
		case now-x.T0 >= r.Grace:
			out, why = append(out, x), append(why, "grace")
		default:
			keep = append(keep, x)
		}
	}
	r.List = keep
	return out, why
}

func (r *CXLReserve) Drop(pod string) {
	keep := r.List[:0]
	for _, x := range r.List {
		if x.Pod != pod {
			keep = append(keep, x)
		}
	}
	r.List = keep
}
