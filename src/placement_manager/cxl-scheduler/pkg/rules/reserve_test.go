package rules

import (
	"math"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-3 }

func TestSlope(t *testing.T) {
	c := MLBECurve
	if !near(Slope(c, 1.0), (1.1062-1.0)/4) || !near(Slope(c, 1.30), (1.4053-1.2437)/4) || !near(Slope(c, 3.0), (2.2787-1.9126)/4) {
		t.Fatal(Slope(c, 1.0), Slope(c, 1.30), Slope(c, 3.0))
	}
}

func newR() *CXLReserve { return &CXLReserve{Curve: MLBECurve, FillRatio: 0.7, FillHold: 0, Grace: 60} }

func TestReserveStacksAndBlocksBurst(t *testing.T) {
	r := newR()
	n := three()
	for i := range n {
		n[i].LatRatio = 1.06
	}
	obs := 1.20
	placed := 0
	for k := 0; k < 5; k++ {
		d := Decide(be, n, r.Effective(obs), prm)
		if d.Tier != "CXL" {
			break
		}
		r.Add("p", float64(k), obs)
		placed++
	}

	if placed != 3 {
		t.Fatal(placed, r.List)
	}
}

func TestReleaseFilledAndGrace(t *testing.T) {
	r := newR()
	a := r.Add("a", 0, 1.20)
	b := r.Add("b", 1, 1.20)
	if !near(b.Eff0, 1.20+a.Delta) {
		t.Fatal(b)
	}
	if out, _ := r.Release(5, 1.21); len(out) != 0 {
		t.Fatal(out)
	}
	out, why := r.Release(6, 1.226)
	if len(out) != 1 || out[0].Pod != "a" || why[0] != "filled" || len(r.List) != 1 {
		t.Fatal(out, why, r.List)
	}
	out, why = r.Release(61, 1.226)
	if len(out) != 1 || why[0] != "grace" || len(r.List) != 0 {
		t.Fatal(out, why)
	}
}

func TestReserveNAAndDrop(t *testing.T) {
	r := newR()
	if r.Effective(-1) != -1 || r.Next(-1) != 0 {
		t.Fatal()
	}
	x := r.Add("n", 0, -1)
	if x.Eff0 != 99 || x.Delta <= 0 {
		t.Fatal(x)
	}
	if out, _ := r.Release(10, 1.5); len(out) != 0 {
		t.Fatal(out)
	}
	r.Drop("n")
	if len(r.List) != 0 {
		t.Fatal(r.List)
	}
}

func TestFillHoldNeedsSustain(t *testing.T) {
	r := &CXLReserve{Curve: MLBECurve, FillRatio: 0.7, FillHold: 5, Grace: 60}
	r.Add("a", 0, 1.00)
	if out, _ := r.Release(4, 1.025); len(out) != 0 {
		t.Fatal(out)
	}
	if out, _ := r.Release(5, 1.005); len(out) != 0 || r.List[0].Since != 0 {
		t.Fatal(out, r.List)
	}
	r.Release(15, 1.03)
	if out, _ := r.Release(19, 1.03); len(out) != 0 {
		t.Fatal(out)
	}
	if out, why := r.Release(20, 1.03); len(out) != 1 || why[0] != "filled" {
		t.Fatal(out, why)
	}
}
