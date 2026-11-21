package main

import "testing"

func TestCPUPoolSpread(t *testing.T) {
	p := newCPUPool("7,8,9")
	got := []string{p.pick("a"), p.pick("b"), p.pick("c"), p.pick("d")}
	if got[0] != "7" || got[1] != "8" || got[2] != "9" || got[3] != "7" {
		t.Fatal(got)
	}
	if p.pick("a") != "7" {
		t.Fatal()
	}
	p.release("b")
	if p.pick("e") != "8" {
		t.Fatal(p.cnt)
	}
}

func TestCPUPoolAdoptAndDisabled(t *testing.T) {
	p := newCPUPool("7,8,9")
	if !p.adopt("x", "9") || p.adopt("y", "0-5") || p.adopt("x", "9") {
		t.Fatal(p.cnt)
	}
	if p.pick("z") != "7" || p.pick("w") != "8" || p.pick("v") != "7" {
		t.Fatal(p.cnt)
	}
	if newCPUPool("").enabled() {
		t.Fatal()
	}
}
